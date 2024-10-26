// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_THREADPOOL_H
#define BITCOIN_UTIL_THREADPOOL_H

#include <sync.h>
#include <util/string.h>
#include <util/thread.h>
#include <util/threadinterrupt.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <stdexcept>
#include <utility>
#include <queue>
#include <thread>
#include <vector>

class ThreadPool {

private:
    Mutex cs_work_queue;
    std::queue<std::function<void()>> m_work_queue GUARDED_BY(cs_work_queue);
    std::condition_variable m_wait_condition;
    std::condition_variable m_condition;
    CThreadInterrupt m_interrupt;
    std::vector<std::thread> m_workers;
    int32_t m_in_flight_task_count GUARDED_BY(cs_work_queue){0};

    void WorkerThread() EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    {
        bool did_first_run{false};
        WAIT_LOCK(cs_work_queue, wait_lock);
        while (!m_interrupt) {
            std::function<void()> task;
            {
                if (did_first_run) {
                    --m_in_flight_task_count;
                    m_wait_condition.notify_all();
                }
                // Wait for the task or until the stop flag is set
                m_condition.wait(wait_lock,[&]() EXCLUSIVE_LOCKS_REQUIRED(cs_work_queue) { return m_interrupt || !m_work_queue.empty(); });

                // If stopped, exit worker.
                if (m_interrupt) {
                    return;
                }

                // Pop the task
                task = std::move(m_work_queue.front());
                m_work_queue.pop();
                ++m_in_flight_task_count;
                did_first_run = true;
            }

            // Execute the task without the lock
            WITH_REVERSE_LOCK(wait_lock, task());
        }
    }

public:
    ThreadPool() = default;

    ~ThreadPool()
    {
        Stop(); // In case it hasn't been stopped.
    }

    void Start(int num_workers)
    {
        if (!m_workers.empty()) throw std::runtime_error("Thread pool already started");

        // Create the workers
        for (int i = 0; i < num_workers; i++) {
            m_workers.emplace_back(&util::TraceThread, "threadpool_worker_" + util::ToString(i), [this] { WorkerThread(); });
        }
    }

    void Stop()
    {
        // Notify workers and join them.
        m_interrupt();
        m_wait_condition.notify_all();
        m_condition.notify_all();
        for (auto& worker : m_workers) {
            worker.join();
        }
        m_workers.clear();
        m_interrupt.reset();
    }

    template<class T> EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    auto Submit(T task) -> std::future<decltype(task())>
    {
        auto ptr_task = std::make_shared<std::packaged_task<decltype(task()) ()>>(std::move(task));
        std::future<decltype(task())> future = ptr_task->get_future();
        {
            LOCK(cs_work_queue);
            m_work_queue.emplace([=]() {
                (*ptr_task)();
            });
        }
        m_condition.notify_one();
        return future;
    }

    // Synchronous processing
    bool ProcessTask() EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    {
        std::function<void()> task;
        {
            LOCK(cs_work_queue);
            if (m_work_queue.empty()) return false;

            // Pop the task
            task = std::move(m_work_queue.front());
            m_work_queue.pop();
        }
        task();
        return true;
    }

    size_t WorkQueueSize() EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    {
        return WITH_LOCK(cs_work_queue, return m_work_queue.size());
    }

    size_t InFlightTasksCount() EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    {
        return WITH_LOCK(cs_work_queue, return m_in_flight_task_count);
    }

    bool IsIdle() EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    {
        return WITH_LOCK(cs_work_queue, return m_interrupt || (m_work_queue.empty() && m_in_flight_task_count == 0));
    }

    void WaitUntilIdle() EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    {
        WAIT_LOCK(cs_work_queue, wait_lock);
        while (!m_interrupt && (!m_work_queue.empty() || m_in_flight_task_count > 0)) {
            m_wait_condition.wait(wait_lock);
        }
    }

    void WaitForProgress() EXCLUSIVE_LOCKS_REQUIRED(!cs_work_queue)
    {
        WAIT_LOCK(cs_work_queue, wait_lock);
        if (!m_interrupt && (!m_work_queue.empty() || m_in_flight_task_count > 0)) {
            m_wait_condition.wait(wait_lock);
        }
    }

    size_t WorkersCount() const
    {
        return m_workers.size();
    }
};

#endif // BITCOIN_UTIL_THREADPOOL_H
