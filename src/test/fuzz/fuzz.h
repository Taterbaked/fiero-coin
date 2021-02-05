// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_TEST_FUZZ_FUZZ_H
#define SYSCOIN_TEST_FUZZ_FUZZ_H

#include <span.h>

#include <cstdint>
#include <functional>
#include <string_view>

using FuzzBufferType = Span<const uint8_t>;

using TypeTestOneInput = std::function<void(FuzzBufferType)>;
using TypeInitialize = std::function<void()>;

void FuzzFrameworkRegisterTarget(std::string_view name, TypeTestOneInput target, TypeInitialize init);

inline void FuzzFrameworkEmptyFun() {}

#define FUZZ_TARGET(name) \
    FUZZ_TARGET_INIT(name, FuzzFrameworkEmptyFun)

#define FUZZ_TARGET_INIT(name, init_fun)                                      \
    void name##_fuzz_target(FuzzBufferType);                                  \
    struct name##_Before_Main {                                               \
        name##_Before_Main()                                                  \
        {                                                                     \
            FuzzFrameworkRegisterTarget(#name, name##_fuzz_target, init_fun); \
        }                                                                     \
    } const static g_##name##_before_main;                                    \
    void name##_fuzz_target(FuzzBufferType buffer)

#endif // SYSCOIN_TEST_FUZZ_FUZZ_H
