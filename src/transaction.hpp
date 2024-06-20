#ifndef TRANSACTION_HPP
#define TRANSACTION_HPP
#include <vector>
#include <cstdint>
#include "types.hpp"
#include <unordered_map>

enum class t_transactiontype: std::uint8_t {
	add_secret_vote = 0,
	add_open_vote = 1,
	generate = 2, ///< generate new coin
	authorize_miner = 3, ///< vout == new miner pk
	authorize_organizer = 4, ///< vout == new organizer pk
	authorize_issuer = 5, ///< vout == new issuer pk
	authorize_voter = 6, ///< vout == new voter pkh
	create_voting = 7,
	coin_join = 8,
	another_voting_protocol = 9,
	hash_personal_data = 10
};

struct c_vin {
	t_hash_type m_txid; ///< txid with proper vout
	t_signature_type m_sign; ///< signature of txid of trasaction contains this vin
	t_public_key_type m_pk;
};

struct c_vout {
	t_hash_type m_pkh;
	uint32_t m_amount;
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

bool operator<(const c_vin &lhs, const c_vin &rhs) noexcept;
bool operator==(const c_vin &lhs, const c_vin &rhs) noexcept;
bool operator!=(const c_vin &lhs, const c_vin &rhs) noexcept;

std::unordered_multimap<std::string, std::vector<unsigned char> > get_metadata_map(const std::vector<unsigned char> & allmetadata);

/**
 * @brief get_metadata_variable_length_field
 * @return [key][1B size of value][value]
 */
std::vector<unsigned char> get_metadata_variable_length_field(const std::string & key, const std::string & value);

#endif // TRANSACTION_HPP
