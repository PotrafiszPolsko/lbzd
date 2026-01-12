#ifndef TRANSACTION_HPP
#define TRANSACTION_HPP
#include <vector>
#include <cstdint>
#include "types.hpp"
#include <unordered_map>

enum class t_transactiontype: std::uint8_t {
	generate = 1, ///< generate new coin
	authorize_miner = 2, ///< vout == new miner pk
	authorize_organizer = 3, ///< vout == new organizer pk
	another_voting_protocol = 4
};

struct c_vin {
	t_hash_type m_txid; ///< txid with proper vout
	t_signature_type m_sign; ///< signature of txid of trasaction contains this vin
	t_public_key_type m_pk;
};

struct c_vout {
	t_hash_type m_pkh;
};

struct c_transaction {
		t_transactiontype m_type;
		std::vector<c_vin> m_vin;
		std::vector<c_vout> m_vout;
		t_hash_type m_txid;
		std::vector<unsigned char> m_allmetadata;
};

bool operator==(const c_transaction &lhs, const c_transaction &rhs) noexcept;
bool operator!=(const c_transaction &lhs, const c_transaction &rhs) noexcept;

bool operator<(const c_vout &lhs, const c_vout &rhs) noexcept;
bool operator==(const c_vout &lhs, const c_vout &rhs) noexcept;

bool operator==(const c_vin &lhs, const c_vin &rhs) noexcept;
bool operator!=(const c_vin &lhs, const c_vin &rhs) noexcept;

#endif // TRANSACTION_HPP
