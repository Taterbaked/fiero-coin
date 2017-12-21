// Copyright (c) 2016-2017 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FEEDBACK_H
#define FEEDBACK_H
#include "script/script.h"
#include "serialize.h"
enum FeedbackUser {
	FEEDBACKNONE=0,
    FEEDBACKBUYER=1,
	FEEDBACKSELLER=2,
	FEEDBACKARBITER=3
};
class CNameTXIDTuple {
public:
	std::vector<unsigned char> first;
	uint256 second;
	std::vector<unsigned char> third;

	ADD_SERIALIZE_METHODS;

	template <typename Stream, typename Operation>
	inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(first);
		READWRITE(second);
		READWRITE(third);
	}

	CNameTXIDTuple(const std::vector<unsigned char> &f, uint256 s, const std::vector<unsigned char> &guid=std::vector<unsigned char>()) {
		first = f;
		second = s;
		third = guid;
	}

	CNameTXIDTuple() {
		SetNull();
	}
	CNameTXIDTuple operator=(const CNameTXIDTuple& other) {
		this->first = other.first;
		this->second = other.second;
		this->third = other.third;
		return *this;
	}
	bool operator==(const CNameTXIDTuple& other) const {
		return this->first == other.first && this->second == other.second && this->third == other.third;
	}
	bool operator!=(const CNameTXIDTuple& other) const {
		return (this->first != other.first || this->second != other.second || this->third != other.third);
	}
	inline void SetNull() {
		second.SetNull();
		first.clear();
		third.clear();
	}
	inline bool IsNotNull() {
		return (!first.empty() || !second.IsNull() || !third.empty());
	}
};
class CFeedback {
public:
	std::vector<unsigned char> vchFeedback;
	unsigned char nRating;
	unsigned char nFeedbackUserTo;
	unsigned char nFeedbackUserFrom;
    CFeedback() {
        SetNull();
    }
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchFeedback);
		READWRITE(VARINT(nRating));
		READWRITE(VARINT(nFeedbackUserFrom));
		READWRITE(VARINT(nFeedbackUserTo));
	}

	friend bool operator==(const CFeedback &a, const CFeedback &b) {
        return (
        a.vchFeedback == b.vchFeedback
		&& a.nRating == b.nRating
		&& a.nFeedbackUserFrom == b.nFeedbackUserFrom
		&& a.nFeedbackUserTo == b.nFeedbackUserTo
        );
    }

	CFeedback operator=(const CFeedback &b) {
        vchFeedback = b.vchFeedback;
		nRating = b.nRating;
		nFeedbackUserFrom = b.nFeedbackUserFrom;
		nFeedbackUserTo = b.nFeedbackUserTo;
        return *this;
    }

	friend bool operator!=(const CFeedback &a, const CFeedback &b) {
        return !(a == b);
    }
	static std::string FeedbackUserToString(const unsigned char nFeedbackUser) {
		switch (nFeedbackUser) {
			case FEEDBACKNONE:			return "NONE";
			case FEEDBACKBUYER:			return "BUYER";
			case FEEDBACKSELLER:		return "SELLER";
			case FEEDBACKARBITER:		return "ARBITER";
			default:                    return "";
		}
	}
    inline void SetNull() {  nRating = 0; nFeedbackUserFrom = 0; nFeedbackUserTo = 0; vchFeedback.clear();}
	inline bool IsNotNull() const { return (  nRating != 0 || nFeedbackUserFrom != 0 || nFeedbackUserTo != 0 || !vchFeedback.empty()); }
};
#endif // FEEDBACK_H