#ifndef C_UTXO_MOCK_HPP
#define C_UTXO_MOCK_HPP

#include "../src/utxo.hpp"
#include <gmock/gmock.h>

class c_utxo_mock : public c_utxo {
	public:
		c_utxo_mock();
		MOCK_METHOD(std::vector<t_public_key_type>, get_all_miners_public_keys, (), (const, override));
		using hash_type_to_voting_metadata = std::pair<t_hash_type, t_voting_metadata>;
		MOCK_METHOD(std::vector<hash_type_to_voting_metadata>, get_all_votings, (), (const, override));
		MOCK_METHOD(t_voting_metadata, get_voting_metadata_by_voting_id, (const t_hash_type & voting_id), (const, override));
		MOCK_METHOD(std::vector<hash_type_to_voting_metadata>, get_all_finished_votings, (), (const, override));
		MOCK_METHOD(std::vector<hash_type_to_voting_metadata>, get_all_active_votings, (), (const, override));
		MOCK_METHOD(std::vector<hash_type_to_voting_metadata>, get_all_waiting_votings, (), (const, override));
		MOCK_METHOD(uint32_t, get_amount_on_pkh, (const t_hash_type & pkh), (const, override));
		MOCK_METHOD(size_t, get_number_of_all_voters, (), (const, override));
		MOCK_METHOD(std::vector<t_public_key_type>, get_parent_list_voter, (const t_public_key_type & voter_pk, const c_blockchain & blockchain), (const, override));
		MOCK_METHOD(std::vector<t_hash_type>, get_txids_of_tx_auth_voter, (const t_public_key_type & pk), (const, override));
		MOCK_METHOD(size_t, get_number_of_miners, (), (const, override));
		MOCK_METHOD(unsigned char, get_voting_status, (const t_hash_type & voting_id), (const, override));
		MOCK_METHOD(t_hash_type, get_hash_of_data_voter, (const t_public_key_type & pk), (const, override));
		MOCK_METHOD(size_t, get_number_voters_in_group, (const t_public_key_type & organizer_pk, const c_blockchain & blockchain), (const, override));
};

#endif // C_UTXO_MOCK_HPP
