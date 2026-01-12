#ifndef C_UTXO_MOCK_HPP
#define C_UTXO_MOCK_HPP

#include "../src/utxo.hpp"
#include <gmock/gmock.h>

class c_utxo_mock : public c_utxo {
	public:
		c_utxo_mock() = default;
		MOCK_METHOD(std::vector<t_public_key_type>, get_all_miners_public_keys, (), (const, override));
		MOCK_METHOD(size_t, get_number_of_miners, (), (const, override));
		MOCK_METHOD(t_hash_type, get_auth_txid, (const t_public_key_type & pkh), (const, override));
		MOCK_METHOD(bool, is_pk_organizer, (const t_public_key_type & pk), (const, override));
		MOCK_METHOD(bool, is_pk_miner, (const t_public_key_type & pk), (const, override));
		MOCK_METHOD(std::vector<t_hash_type>, get_hashes_of_voting_protocols, (), (const, override));
		MOCK_METHOD(t_hash_type, get_voting_protocol_txid, (const t_hash_type & hash_voting_protocol), (const, override));
};

#endif // C_UTXO_MOCK_HPP
