#include "transaction.hpp"
#include "utils.hpp"
#include <sodium.h>
#include <limits>
#include <cstddef>

bool operator==(const c_transaction &lhs, const c_transaction &rhs) noexcept {
	if (lhs.m_type!=rhs.m_type) return false;
	if (lhs.m_txid!=rhs.m_txid) return false;
	if (lhs.m_allmetadata!=rhs.m_allmetadata) return false;
	for (const auto & vin : lhs.m_vin) {
		const auto it = std::find(rhs.m_vin.cbegin(), rhs.m_vin.cend(), vin);
		if (it == rhs.m_vin.cend()) return false;
	}
	for (const auto & vout : lhs.m_vout) {
		const auto it = std::find(rhs.m_vout.cbegin(), rhs.m_vout.cend(), vout);
		if (it == rhs.m_vout.cend()) return false;
	}
	return true;
}

bool operator!=(const c_transaction &lhs, const c_transaction &rhs) noexcept {
	return !(lhs == rhs);
}

bool operator<(const c_vout &lhs, const c_vout &rhs) noexcept {
	return lhs.m_pkh < rhs.m_pkh;
}

bool operator==(const c_vout &lhs, const c_vout &rhs) noexcept {
	if (lhs.m_pkh != rhs.m_pkh) return false;
	return true;
}

bool operator==(const c_vin &lhs, const c_vin &rhs) noexcept {
	if (lhs.m_pk != rhs.m_pk) return false;
	if (lhs.m_sign != rhs.m_sign) return false;
	if (lhs.m_txid != rhs.m_txid) return false;
	return true;
}

bool operator!=(const c_vin &lhs, const c_vin &rhs) noexcept {
	return !(lhs == rhs);
}
