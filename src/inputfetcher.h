// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INPUTFETCHER_H
#define BITCOIN_INPUTFETCHER_H

#include <coins.h>
#include <sync.h>
#include <tinyformat.h>
#include <txdb.h>
#include <util/threadpool.h>

#include <algorithm>
#include <iterator>
#include <set>
#include <vector>

/**
 * Input fetcher for fetching inputs from the CoinsDB and inserting
 * into the CoinsTip.
 *
 * The main thread pushes batches of outpoints
 * onto the queue, where they are fetched by N worker threads. The resulting
 * coins are pushed onto another queue after they are read from disk. When
 * the main is done adding outpoints, it starts writing the results of the read
 * queue to the cache.
 */
class InputFetcher
{
private:
    //! Mutex to protect the inner state
    Mutex m_mutex{};

    //! The queue of pairs to be written to the cache.
    std::vector<std::pair<COutPoint, Coin>> m_pairs GUARDED_BY(m_mutex){};

    //! The maximum number of outpoints to be processed in one batch
    const uint32_t m_batch_size;
    std::shared_ptr<ThreadPool> m_thread_pool;

    //! DB to fetch from.
    const CCoinsViewDB* m_db{nullptr};

    //! Add a batch of outpoints to the queue
    void Add(std::vector<COutPoint>&& outpoints) noexcept
    {
        if (!outpoints.empty()) {
            return;
        }

        m_thread_pool->Submit([this, outpoints = std::move(outpoints)]() {
            const uint32_t batch_size = std::max(1U, std::min(m_batch_size, static_cast<uint32_t>(outpoints.size() / m_thread_pool->WorkersCount())));
            uint32_t i{0};
            std::vector<COutPoint> local_outpoints{};
            local_outpoints.reserve(batch_size);
            for (auto it{outpoints.begin()}; it != outpoints.end(); ++i, ++it) {
                local_outpoints.emplace_back(*it);
                if (i == batch_size || std::next(it) == outpoints.end()) {
                    m_thread_pool->Submit([this, outpoints = std::move(local_outpoints)]() {
                        std::vector<std::pair<COutPoint, Coin>> pairs{};
                        pairs.reserve(outpoints.size());
                        for (const COutPoint& outpoint : outpoints) {
                            if (auto coin{m_db->GetCoin(outpoint)}; coin) {
                                pairs.emplace_back(outpoint, std::move(*coin));
                            } else {
                                // Missing an input, just break. This block will fail validation, so no point in continuing.
                                break;
                            }
                        }
                        {
                            LOCK(m_mutex);
                            if (m_pairs.empty()) {
                                m_pairs = std::move(pairs);
                            } else {
                                m_pairs.reserve(m_pairs.size() + pairs.size());
                                m_pairs.insert(m_pairs.end(), std::make_move_iterator(pairs.begin()),
                                                std::make_move_iterator(pairs.end()));
                            }
                        }
                    });
                    i = 0;
                    local_outpoints = std::vector<COutPoint>{};
                    if (std::next(it) != outpoints.end()) {
                        local_outpoints.reserve(batch_size);
                    }
                }
            }
        });
    }


public:
    //! Create a new input fetcher
    explicit InputFetcher(uint32_t batch_size, std::shared_ptr<ThreadPool> thread_pool) noexcept
        : m_batch_size(batch_size), m_thread_pool(thread_pool)
    {
    }

    //! Fetch all block inputs from db, and insert into cache.
    void FetchInputs(CCoinsViewCache& cache, const CCoinsViewDB& db, const CBlock& block) noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    {
        m_db = &db;

        std::vector<COutPoint> buffer{};
        buffer.reserve(m_batch_size);
        std::set<Txid> txids{};
        for (const auto& tx : block.vtx) {
            if (tx->IsCoinBase()) continue;
            for (const auto& in : tx->vin) {
                const auto& outpoint = in.prevout;
                // If an input references an outpoint from earlier in the
                // block, it won't be in the cache yet but it also won't be
                // in the db either.
                if (txids.contains(outpoint.hash)) {
                    continue;
                }
                if (cache.HaveCoinInCache(outpoint)) {
                    continue;
                }

                buffer.emplace_back(outpoint);
                if (buffer.size() == m_batch_size) {
                    Add(std::move(buffer));
                    buffer.clear();
                    buffer.reserve(m_batch_size);
                }
            }
            txids.insert(tx->GetHash());
        }

        Add(std::move(buffer));

        std::vector<std::pair<COutPoint, Coin>> pairs{};
        do {
            {
                WAIT_LOCK(m_mutex, lock);
                while (m_pairs.empty()) {
                    if (m_thread_pool->IsIdle()) {
                        return;
                    }
                    m_thread_pool->WaitForProgress();
                }

                pairs = std::move(m_pairs);
                m_pairs.clear();
            }

            for (auto& pair : pairs) {
                cache.EmplaceCoinInternalDANGER(std::move(pair.first), std::move(pair.second), /*set_dirty=*/false);
            }
        } while (true);
    }

    bool HasThreads() const { return m_thread_pool->WorkersCount() > 0; }
};

#endif // BITCOIN_INPUTFETCHER_H
