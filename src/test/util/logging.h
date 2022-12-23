// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_LOGGING_H
#define BITCOIN_TEST_UTIL_LOGGING_H

#include <util/macros.h>

#include <functional>
#include <list>
#include <string>

class DebugLogHelper
{
public:
    using MatchFn = std::function<bool(const std::string* line)>;

    explicit DebugLogHelper(std::string message, MatchFn match = [](const std::string*){ return true; });

    ~DebugLogHelper();

private:
    const std::string m_message;
    bool m_found{false};
    std::list<std::function<void(const std::string&)>>::iterator m_print_connection;

    //! Custom match checking function.
    //!
    //! Invoked with pointers to lines containing matching strings, and with
    //! nullptr if ~DebugLogHelper() is called without any successful match.
    //!
    //! Can return true to enable default DebugLogHelper behavior of:
    //! (1) ending search after first successful match, and
    //! (2) raising an error in ~DebugLogHelper() if no match was found (will be called with nullptr then)
    //! Can return false to do the opposite in either case.
    MatchFn m_match;

    bool m_receiving_log;
    void StopReceivingLog();
};

#define ASSERT_DEBUG_LOG(message) DebugLogHelper UNIQUE_NAME(debugloghelper)(message)

#endif // BITCOIN_TEST_UTIL_LOGGING_H
