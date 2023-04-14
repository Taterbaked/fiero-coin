// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/connection_types.h>
#include <protocol.h>

#include <array>
#include <atomic>
#include <cstddef>

/**
 * Placeholder for total network traffic. Split by direction, network, connection
 * type and message type (byte and message counts).
 */
class NetStats
{
public:
    struct MsgStat {
        std::atomic_uint64_t byte_count; //!< Number of bytes transferred.
        std::atomic_uint64_t msg_count;  //!< Number of messages transferred.

        MsgStat() = default;

        MsgStat(const MsgStat& x) : byte_count{x.byte_count.load()}, msg_count{x.msg_count.load()} {}

        MsgStat(std::atomic_uint64_t x, std::atomic_uint64_t y) : byte_count{x.load()}, msg_count{y.load()} {}
    };

    enum class Direction { SENT,
                            RECV };

    /// Number of elements in `Direction`.
    static constexpr size_t NUM_DIRECTIONS{2};

    using MultiDimensionalStats = std::array<std::array<std::array<std::array<MsgStat,
                                                                              // add 1 for the other message type
                                                                              NUM_NET_MESSAGE_TYPES + 1>,
                                                                   NUM_CONNECTION_TYPES>,
                                                        NET_MAX>,
                                             NUM_DIRECTIONS>;

    MultiDimensionalStats m_data;

    // The ...FromIndex() and ...ToIndex() methods below convert from/to
    // indexes of `m_data[]` to the actual values they represent. For example,
    // assuming MessageTypeToIndex("ping") == 15, then everything stored in
    // m_data[x][y][z][15] is traffic from "ping" messages (for any x, y or z).

    [[nodiscard]] static Direction DirectionFromIndex(size_t index);
    [[nodiscard]] static Network NetworkFromIndex(size_t index);
    [[nodiscard]] static ConnectionType ConnectionTypeFromIndex(size_t index);

private:
    // Helper methods to make sure the indexes associated with enums are reliable
    [[nodiscard]] static size_t DirectionToIndex(Direction direction);
    [[nodiscard]] static size_t NetworkToIndex(Network net);
    [[nodiscard]] static size_t ConnectionTypeToIndex(ConnectionType conn_type);
};
