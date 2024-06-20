#ifndef BLOCKCHAIN_MODULE_MOCK_HPP
#define BLOCKCHAIN_MODULE_MOCK_HPP

#include <gmock/gmock.h>
#include "../src/blockchain_module.hpp"
#include "mediator_stub.hpp"

class c_blockchain_module_mock : public c_blockchain_module {
	public:
		c_blockchain_module_mock();
		MOCK_METHOD(void, add_new_block, (const c_block & block), (override));
		MOCK_METHOD(c_transaction, get_transaction, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(c_block, get_block_at_height, (const size_t height), (const, override));
		MOCK_METHOD(c_block, get_block_at_hash, (const t_hash_type & hash), (const, override));
		MOCK_METHOD(t_hash_type, get_last_block_hash, (), (const, override));
		MOCK_METHOD(size_t, get_number_of_mempool_transactions, (), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_mempool_transactions, (), (const, override));
		MOCK_METHOD(proto::block, get_block_at_hash_proto, (const t_hash_type & block_hash), (const, override));
		MOCK_METHOD(std::vector<proto::header>, get_headers_proto, (const t_hash_type & hash_begin, const t_hash_type & hash_end), (const, override));
		MOCK_METHOD(bool, is_pk_organizer, (const t_public_key_type & organizer_pk), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_voter_auth_tx, (const t_public_key_type & voter_pk), (const, override));
		MOCK_METHOD(t_hash_type, get_hash_personal_data, (const t_public_key_type & voter_pk), (const, override));
		MOCK_METHOD(bool, is_pk_voter, (const t_public_key_type & voter_pk), (const, override));
		MOCK_METHOD(size_t, get_height, (), (const, override));
		MOCK_METHOD(uint32_t, get_amount_pkh, (const t_hash_type & pkh), (const, override));
		MOCK_METHOD(size_t, get_number_of_all_voters_in_group, (const t_public_key_type & organizer_pk), (const, override));
		MOCK_METHOD(std::vector<t_authorization_data>, get_authorization_data, (const t_public_key_type & pk), (const, override));
		using voting_data = std::pair<t_hash_type, t_voting_metadata>;
		MOCK_METHOD(std::vector<voting_data> , get_all_active_votings_for_voter, (const t_public_key_type & voter_pk), (const, override));
		MOCK_METHOD(bool, check_the_voter_voted, (const t_public_key_type & voter_pk, const t_hash_type & voting_id), (const, override));
		MOCK_METHOD(t_hash_type, get_voter_auth_txid_for_voting, (const t_public_key_type & voter_pk, const t_hash_type & voting_id), (const, override));
		MOCK_METHOD(t_voting_metadata, get_voting_details, (const t_hash_type & voting_id), (const, override));
		MOCK_METHOD(t_hash_type, get_source_txid, (const t_hash_type & pkh), (const, override));
		MOCK_METHOD(uint32_t, get_last_block_time, (), (const, override));
		MOCK_METHOD(c_block, get_block_by_txid, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_all_vote_transactions, (const t_hash_type & voting_id), (const, override));
		MOCK_METHOD(std::vector<t_hash_type>, get_merkle_branch, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(t_hash_type, get_block_id_by_txid, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(std::vector<t_public_key_type>, get_voter_groups, (const t_public_key_type & voter_pk), (const, override));
		MOCK_METHOD(size_t, get_number_of_all_voters, (), (const, override));
		MOCK_METHOD(size_t, get_number_of_miners, (), (const, override));
		MOCK_METHOD(std::vector<voting_data>, get_all_active_votings, (), (const, override));
		MOCK_METHOD(std::vector<voting_data>, get_all_votings, (), (const, override));
		MOCK_METHOD(std::vector<voting_data>, get_all_inactive_votings, (), (const, override));
		MOCK_METHOD(size_t, get_all_added_votes, (), (const, override));
		MOCK_METHOD(size_t, get_number_of_transactions, (), (const, override));
		MOCK_METHOD(std::vector<c_block_record>, get_last_5_blocks, (), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_last_5_transactions, (), (const, override));
		MOCK_METHOD(std::vector<voting_data>, get_last_5_votings, (), (const, override));
		using voting_id_to_bool = std::pair<t_hash_type, bool>;
		MOCK_METHOD(std::vector<voting_id_to_bool>, finished_or_active_votings, (const std::vector<voting_data> &votings), (const, override));
		MOCK_METHOD(std::vector<t_hash_type>, get_waiting_votings_ids, (const std::vector<voting_data> &votings), (const, override));
		using voting_id_to_double = std::pair<t_hash_type, double>;
		MOCK_METHOD(std::vector<voting_id_to_double>, get_voter_turnout_from_specific_votes, (const std::vector<voting_data> &votings), (const, override));
		MOCK_METHOD(std::vector<c_block_record>, get_sorted_blocks, (const size_t amount_of_blocks), (const, override));
		using vector_blocks_record_to_size = std::pair<std::vector<c_block_record>, size_t>;
		MOCK_METHOD(vector_blocks_record_to_size, get_sorted_blocks_per_page, (const size_t offset), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_latest_transactions, (const size_t amount_txs), (const, override));
		using vector_transaction_to_size = std::pair<std::vector<c_transaction>, size_t>;
		MOCK_METHOD(vector_transaction_to_size, get_txs_per_page, (const size_t offset), (const, override));
		using voting_id_to_map_string_to_uint = std::pair<t_hash_type, std::unordered_map<std::string, uint32_t>>;
		MOCK_METHOD(std::vector<voting_id_to_map_string_to_uint>, get_votings_results_from_specific_votes, (const std::vector<voting_data> &votings), (const, override));
		using voting_data_vector_to_size = std::pair<std::vector<voting_data>, size_t>;
		MOCK_METHOD(voting_data_vector_to_size, get_all_votings_by_name_or_voting_id_with_number_votings, (const size_t offset, const std::string &voting_name_or_id), (const, override));
		MOCK_METHOD(std::vector<voting_data>, get_latest_votings, (const size_t amount_votings), (const, override));
		MOCK_METHOD(voting_data_vector_to_size, get_votings_per_page, (const size_t offset), (const, override));
		MOCK_METHOD(vector_transaction_to_size, get_txs_from_block_per_page, (const size_t offset, const t_hash_type &block_id), (const, override));
		using signature_to_pk_vector_to_size = std::pair<std::vector<std::pair<t_signature_type, t_public_key_type>>, size_t>;
		MOCK_METHOD(signature_to_pk_vector_to_size, get_block_signatures_and_pk_miners_per_page, (const size_t offset, const t_hash_type &block_id), (const, override));
		MOCK_METHOD(std::vector<voting_data>, get_all_finished_votings, (), (const, override));
		MOCK_METHOD(double, get_voter_turnout_from_vote, (const t_hash_type & voting_id), (const, override));
		using map_string_to_uint = std::unordered_map<std::string, uint32_t>;
		MOCK_METHOD(map_string_to_uint,  get_voting_result, (const t_hash_type & voting_id), (const, override));
		MOCK_METHOD(unsigned char, get_voting_status, (const t_hash_type &voting_id), (const, override));
		MOCK_METHOD(bool, is_transaction_in_blockchain, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(bool, is_pk_issuer, (const t_public_key_type & issuer_pk), (const, override));
		MOCK_METHOD(bool, is_blockchain_synchronized, (), (const, override));
		MOCK_METHOD(bool, block_exists, (const t_hash_type & block_id), (const, override));
	private:
		static c_mediator_stub m_mediator_stub;
};

#endif // BLOCKCHAIN_MODULE_MOCK_HPP
