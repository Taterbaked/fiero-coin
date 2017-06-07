// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_COINCONTROL_H
#define BITCOIN_WALLET_COINCONTROL_H

#include "policy/feerate.h"
#include "primitives/transaction.h"
#include "wallet/wallet.h"
#include <map>

/** Coin Control Features. */
class CCoinControl
{
public:
    CTxDestination destChange;
    //! If false, allows unselected inputs, but requires all selected inputs be used
    bool fAllowOtherInputs;
    //! Includes watch only addresses which match the ISMINE_WATCH_SOLVABLE criteria
    bool fAllowWatchOnly;
    //! Override estimated feerate
    bool fOverrideFeeRate;
    //! Feerate to use if overrideFeeRate is true
    CFeeRate nFeeRate;
    //! Override the default confirmation target, 0 = use default
    int nConfirmTarget;
    //! Signal BIP-125 replace by fee.
    bool signalRbf;

    CCoinControl()
    {
        SetNull();
    }

    void SetNull()
    {
        destChange = CNoDestination();
        fAllowOtherInputs = false;
        fAllowWatchOnly = false;
        setSelected.clear();
        nFeeRate = CFeeRate(0);
        fOverrideFeeRate = false;
        nConfirmTarget = 0;
        signalRbf = fWalletRbf;
    }

    bool HasSelected() const
    {
        return (setSelected.size() > 0);
    }

    bool IsSelected(const COutPoint& output) const
    {
        return (setSelected.count(output) > 0);
    }

    void Select(const COutPoint& output)
    {
        setSelected.insert(output);
    }

    void UnSelect(const COutPoint& output)
    {
        setSelected.erase(output);
    }

    void UnSelectAll()
    {
        setSelected.clear();
    }

    void ListSelected(std::vector<COutPoint>& vOutpoints) const
    {
        vOutpoints.assign(setSelected.begin(), setSelected.end());
    }

    void AddKnownCoins(const CInputCoin& coin)
    {
        knownCoins.insert(std::make_pair(coin.outpoint, coin));
    }

    boost::optional<CInputCoin> FindKnownCoin(const COutPoint& outpoint) const
    {
        boost::optional<CInputCoin> foundCoin;
        auto it = knownCoins.find(outpoint);
        if (it != knownCoins.end())
            foundCoin = it->second;
        return foundCoin;
    }

private:
    std::set<COutPoint> setSelected;
    //! A map of known UTXO
    std::map<COutPoint, CInputCoin> knownCoins;
};

#endif // BITCOIN_WALLET_COINCONTROL_H
