// Copyright (c) 2022 The Navcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NAVCOIN_BLSCT_ARITH_RANGE_PROOF_CONFIG_H
#define NAVCOIN_BLSCT_ARITH_RANGE_PROOF_CONFIG_H

#include <cstddef>

class Config
{
public:
    // maximum # of retries allowed for RangeProof::Prove function
    inline static const size_t max_prove_func_retries = 100;

    // size of each input value in bits
    inline static const size_t m_bit_size = 64;

    // maximum # of input values
    inline static const size_t m_max_value_len = 16;

    inline static const size_t m_max_message_size = 54;
    inline static const size_t m_max_value_vec_len = m_max_value_len * m_bit_size;
};

#endif // NAVCOIN_BLSCT_ARITH_RANGE_PROOF_CONFIG_H