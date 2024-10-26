// Copyright (c) 2012-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKQUEUE_H
#define BITCOIN_CHECKQUEUE_H

#include <sync.h>
#include <util/threadpool.h>

#include <algorithm>
#include <iterator>
#include <vector>

/**
 * Queue for verifications that have to be performed.
  * The verifications are represented by a type T, which must provide an
  * operator(), returning a bool.
  *
  * One thread (the master) is assumed to push batches of verifications
  * onto the queue, where they are processed by N-1 worker threads. When
  * the master is done adding work, it temporarily joins the worker pool
  * as an N'th worker, until all jobs are done.
  */
template <typename T>
class CCheckQueue
{
private:
    //! The temporary evaluation result.
    std::atomic<bool> m_all_ok{true};

    //! The maximum number of elements to be processed in one batch
    const unsigned int nBatchSize;
    std::shared_ptr<ThreadPool> m_thread_pool;

    void Check(std::vector<T>&& checks) noexcept
    {
        bool ok{m_all_ok};
        if (!ok) return;
        for  (T& check : checks)
            if (ok)
                ok = check();
        if (!ok) m_all_ok = false;
    }

    void CheckBatch(std::vector<T>&& checks) noexcept
    {
        const uint32_t batch_size = std::max(1U, std::min(nBatchSize, static_cast<uint32_t>(checks.size() / (m_thread_pool->WorkersCount() + 1))));
        uint32_t i{0};
        std::vector<T> local_checks{};
        local_checks.reserve(batch_size);
        for (auto it{checks.begin()}; it != checks.end(); ++i, ++it) {
            local_checks.emplace_back(std::move(*it));
            if (i == batch_size || std::next(it) == checks.end()) {
                m_thread_pool->Submit([this, checks = std::move(local_checks)]() mutable {
                    Check(std::move(checks));
                });
                i = 0;
                local_checks = std::vector<T>{};
                if (std::next(it) != checks.end()) {
                    local_checks.reserve(batch_size);
                }
            }
        }
    }

public:
    //! Mutex to ensure only one concurrent CCheckQueueControl
    Mutex m_control_mutex;

    //! Create a new check queue
    explicit CCheckQueue(unsigned int batch_size, std::shared_ptr<ThreadPool> thread_pool)
        : nBatchSize(batch_size), m_thread_pool(thread_pool)
    {
    }

    //! Wait until execution finishes, and return whether all evaluations were successful.
    bool Wait()
    {
        while (m_thread_pool->ProcessTask()) {}
        m_thread_pool->WaitUntilIdle();
        const bool ret{m_all_ok};
        m_all_ok = true;
        return ret;
    }

    //! Add a batch of checks to the queue
    void Add(std::vector<T>&& checks) noexcept
    {
        if (!m_all_ok || checks.empty()) {
            return;
        }

        m_thread_pool->Submit([this, checks = std::move(checks)]() mutable {
            CheckBatch(std::move(checks));
        });
    }

    bool HasThreads() const noexcept { return m_thread_pool->WorkersCount() > 0; }
};

/**
 * RAII-style controller object for a CCheckQueue that guarantees the passed
 * queue is finished before continuing.
 */
template <typename T>
class CCheckQueueControl
{
private:
    CCheckQueue<T> * const pqueue;
    bool fDone;

public:
    CCheckQueueControl() = delete;
    CCheckQueueControl(const CCheckQueueControl&) = delete;
    CCheckQueueControl& operator=(const CCheckQueueControl&) = delete;
    explicit CCheckQueueControl(CCheckQueue<T> * const pqueueIn) : pqueue(pqueueIn), fDone(false)
    {
        // passed queue is supposed to be unused, or nullptr
        if (pqueue != nullptr) {
            ENTER_CRITICAL_SECTION(pqueue->m_control_mutex);
        }
    }

    bool Wait()
    {
        if (pqueue == nullptr)
            return true;
        bool fRet = pqueue->Wait();
        fDone = true;
        return fRet;
    }

    void Add(std::vector<T>&& vChecks)
    {
        if (pqueue != nullptr) {
            pqueue->Add(std::move(vChecks));
        }
    }

    ~CCheckQueueControl()
    {
        if (!fDone)
            Wait();
        if (pqueue != nullptr) {
            LEAVE_CRITICAL_SECTION(pqueue->m_control_mutex);
        }
    }
};

#endif // BITCOIN_CHECKQUEUE_H
