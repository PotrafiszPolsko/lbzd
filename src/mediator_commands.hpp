#ifndef MEDIATOR_COMMANDS_HPP
#define MEDIATOR_COMMANDS_HPP

#include "block.hpp"
#include "transaction.hpp"
#include "blockchain.hpp"
#include "shared_mutex"
#include "authorization_level_data.hpp"
#include "rpc_authorization_data.hpp"
#include "params.hpp"
#include "peer_reference.hpp"

enum class t_mediator_cmd_type {
	e_get_tx = 0,
	e_get_block_by_height = 1,
	e_get_block_by_id = 2,
	e_get_last_block_hash = 3,
	e_add_new_block = 4,
	e_broadcast_block = 6,
	e_broadcast_transaction = 7,
	e_get_mempool_size = 8,
	e_get_mempool_transactions = 10,
	e_get_all_active_voting_ids = 11,
	e_get_blockchain_ref = 12, // for simulation only
	e_get_block_by_id_proto = 13,
	e_get_headers_proto = 14,
	e_is_organizer_pk = 15,
	e_get_voter_auth_data = 22,
	e_get_personal_data = 24,
	e_get_height = 27,
	e_get_voting_results = 28,
	e_is_authorized = 30,
	e_get_all_active_votings_for_voter = 32,
	e_get_amount_on_pkh = 34,
	e_check_voter_voted = 36,
	e_get_voter_auth_txid_for_voting = 37,
	e_get_voting_details = 40,
	e_get_source_txid_for_pkh = 42,
	e_get_peers = 45,
	e_get_metadata_from_tx = 48,
	e_get_last_block_time = 50,
	e_get_block_by_txid = 51,
	e_get_all_vote_transactions = 52,
	e_get_merkle_branch = 53,
	e_get_voter_groups = 54,
	e_get_number_of_all_voters = 56,
	e_get_number_of_miners = 57,
	e_get_number_of_all_votings = 58,
	e_get_number_of_all_inactive_votings = 59,
	e_get_number_of_all_added_votes = 60,
	e_get_number_of_all_transactions = 61,
	e_get_last_5_blocks = 62,
	e_get_last_5_transactions = 63,
	e_get_last_5_votings = 64,
	e_get_block_by_id_without_txs_and_signs = 65,
	e_get_block_by_height_without_txs_and_signs = 66,
	e_get_block_by_txid_without_txs_and_signs = 67,
	e_get_sorted_blocks = 68,
	e_get_sorted_blocks_per_page = 69,
	e_get_latest_txs = 70,
	e_get_txs_per_page = 71,
	e_get_votings_by_name_or_id = 72,
	e_get_latest_votings = 73,
	e_get_votings_per_page = 74,
	e_get_txs_from_block_per_page = 75,
	e_get_block_signatures_and_pk_miners_per_page = 76,
	e_get_number_of_all_active_votings = 77,
	e_get_number_of_all_finished_votings = 78,
	e_get_voting_by_id = 79,
	e_is_blockchain_synchronized = 80,
	e_get_all_finished_votings_for_voter = 81,
	e_block_exists = 82
};

struct t_mediator_command_request {
	t_mediator_command_request(t_mediator_cmd_type type) : m_type(type){}
	virtual ~t_mediator_command_request() = default;
	t_mediator_cmd_type m_type;
};

struct t_mediator_command_response {
	t_mediator_command_response(t_mediator_cmd_type type) : m_type(type){}
	virtual ~t_mediator_command_response() = default;
	t_mediator_cmd_type m_type;
};

struct t_mediator_command_request_get_tx : public t_mediator_command_request {
	t_mediator_command_request_get_tx() : t_mediator_command_request(t_mediator_cmd_type::e_get_tx){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_tx : public t_mediator_command_response {
	t_mediator_command_response_get_tx() : t_mediator_command_response(t_mediator_cmd_type::e_get_tx){}
	c_transaction m_transaction;
};

struct t_mediator_command_request_get_block_by_height : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_height() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_height){}
	size_t m_height;
};

struct t_mediator_command_response_get_block_by_height : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_height() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_height){}
	c_block m_block;
};

struct t_mediator_command_request_get_block_by_id : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_id() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_id){}
	t_hash_type m_block_hash;
};

struct t_mediator_command_response_get_block_by_id : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_id() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_id){}
	c_block m_block;
};

struct t_mediator_command_request_get_last_block_hash : public t_mediator_command_request {
	t_mediator_command_request_get_last_block_hash() : t_mediator_command_request(t_mediator_cmd_type::e_get_last_block_hash){}
};

struct t_mediator_command_response_get_last_block_hash : public t_mediator_command_response {
	t_mediator_command_response_get_last_block_hash() : t_mediator_command_response(t_mediator_cmd_type::e_get_last_block_hash){}
	t_hash_type m_last_block_hash;
};

struct t_mediator_command_request_add_new_block : public t_mediator_command_request {
	t_mediator_command_request_add_new_block() : t_mediator_command_request(t_mediator_cmd_type::e_add_new_block){}
	c_block m_block;
};

struct t_mediator_command_response_add_new_block : public t_mediator_command_response {
	t_mediator_command_response_add_new_block() : t_mediator_command_response(t_mediator_cmd_type::e_add_new_block){}
	bool m_is_blockchain_synchronized = false;
	bool m_is_block_exists = false;
};

struct t_mediator_command_request_broadcast_block : public t_mediator_command_request {
	t_mediator_command_request_broadcast_block() : t_mediator_command_request(t_mediator_cmd_type::e_broadcast_block){}
	c_block m_block;
};

struct t_mediator_command_response_broadcast_block : public t_mediator_command_response {
	t_mediator_command_response_broadcast_block() : t_mediator_command_response(t_mediator_cmd_type::e_broadcast_block){}
};

struct t_mediator_command_request_broadcast_transaction : public t_mediator_command_request {
	t_mediator_command_request_broadcast_transaction() : t_mediator_command_request(t_mediator_cmd_type::e_broadcast_transaction){}
	c_transaction m_transaction;
};

struct t_mediator_command_response_broadcast_transaction : public t_mediator_command_response {
	t_mediator_command_response_broadcast_transaction() : t_mediator_command_response(t_mediator_cmd_type::e_broadcast_transaction){}
};

struct t_mediator_command_request_get_mempool_size : public t_mediator_command_request {
	t_mediator_command_request_get_mempool_size() : t_mediator_command_request(t_mediator_cmd_type::e_get_mempool_size){}
};

struct t_mediator_command_response_get_mempool_size : public t_mediator_command_response {
	t_mediator_command_response_get_mempool_size() : t_mediator_command_response(t_mediator_cmd_type::e_get_mempool_size){}
	size_t m_number_of_transactions;
	// size_t m_mempool_size_in_bytes;
};

struct t_mediator_command_request_get_mempool_transactions : public t_mediator_command_request {
	t_mediator_command_request_get_mempool_transactions() : t_mediator_command_request(t_mediator_cmd_type::e_get_mempool_transactions){}
};

struct t_mediator_command_response_get_mempool_transactions : public t_mediator_command_response {
	t_mediator_command_response_get_mempool_transactions() : t_mediator_command_response(t_mediator_cmd_type::e_get_mempool_transactions){}
	std::vector<c_transaction> m_transactions;
};

struct t_mediator_command_request_get_all_active_voting_ids : public t_mediator_command_request {
	t_mediator_command_request_get_all_active_voting_ids() : t_mediator_command_request(t_mediator_cmd_type::e_get_all_active_voting_ids){}
};

struct t_mediator_command_response_get_all_active_voting_ids : public t_mediator_command_response {
	t_mediator_command_response_get_all_active_voting_ids() : t_mediator_command_response(t_mediator_cmd_type::e_get_all_active_voting_ids){}
	std::vector<t_hash_type> m_voting_ids;
};

struct t_mediator_command_request_get_blockchain_ref : public t_mediator_command_request {
	t_mediator_command_request_get_blockchain_ref() : t_mediator_command_request(t_mediator_cmd_type::e_get_blockchain_ref){}
};

class c_utxo;
struct t_mediator_command_response_get_blockchain_ref : public t_mediator_command_response {
	t_mediator_command_response_get_blockchain_ref() : t_mediator_command_response(t_mediator_cmd_type::e_get_blockchain_ref){}
	c_blockchain *m_blockchain;
	std::shared_mutex *m_blockchain_mtx;
	c_utxo *m_utxo;
};

struct t_mediator_command_request_get_block_by_id_proto : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_id_proto() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_id_proto){}
	t_hash_type m_block_hash;
};

struct t_mediator_command_response_get_block_by_id_proto : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_id_proto() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_id_proto){}
	proto::block m_block_proto;
};

// get headers (m_hash_begin; m_hash_end]
struct t_mediator_command_request_get_headers_proto : public t_mediator_command_request {
	t_mediator_command_request_get_headers_proto() : t_mediator_command_request(t_mediator_cmd_type::e_get_headers_proto){}
	t_hash_type m_hash_begin;
	t_hash_type m_hash_end; // if 0-filled get as many headers as possible (max 2000)
};

struct t_mediator_command_response_get_headers_proto : public t_mediator_command_response {
	t_mediator_command_response_get_headers_proto() : t_mediator_command_response(t_mediator_cmd_type::e_get_headers_proto){}
	std::vector<proto::header> m_headers;
};

struct t_mediator_command_request_is_organizer_pk : public t_mediator_command_request {
	t_mediator_command_request_is_organizer_pk() : t_mediator_command_request(t_mediator_cmd_type::e_is_organizer_pk){}
	t_public_key_type m_pk;
};

struct t_mediator_command_response_is_organizer_pk : public t_mediator_command_response {
	t_mediator_command_response_is_organizer_pk() : t_mediator_command_response(t_mediator_cmd_type::e_is_organizer_pk){}
	bool m_is_organizer_pk;
};

struct t_mediator_command_request_get_voter_auth_data : public t_mediator_command_request {
	t_mediator_command_request_get_voter_auth_data() : t_mediator_command_request(t_mediator_cmd_type::e_get_voter_auth_data){}
	t_public_key_type m_pk_voter;
};

struct t_mediator_command_response_get_voter_auth_data : public t_mediator_command_response {
	t_mediator_command_response_get_voter_auth_data() : t_mediator_command_response(t_mediator_cmd_type::e_get_voter_auth_data){}
	std::map<t_public_key_type, uint32_t> m_auth_level;
};

struct t_mediator_command_request_get_personal_data : public t_mediator_command_request {
	t_mediator_command_request_get_personal_data() : t_mediator_command_request(t_mediator_cmd_type::e_get_personal_data){}
	t_public_key_type m_pk_voter;
};

struct t_mediator_command_response_get_personal_data : public t_mediator_command_response {
	t_mediator_command_response_get_personal_data() : t_mediator_command_response(t_mediator_cmd_type::e_get_personal_data){}
	t_hash_type m_hash_personal_data;
};

struct t_mediator_command_request_get_height : public t_mediator_command_request {
	t_mediator_command_request_get_height() : t_mediator_command_request(t_mediator_cmd_type::e_get_height){}
};

struct t_mediator_command_response_get_height : public t_mediator_command_response {
	t_mediator_command_response_get_height() : t_mediator_command_response(t_mediator_cmd_type::e_get_height){}
	size_t m_height;
};

struct t_mediator_command_request_get_voting_results : public t_mediator_command_request {
	t_mediator_command_request_get_voting_results() : t_mediator_command_request(t_mediator_cmd_type::e_get_voting_results){}
	t_hash_type m_txid_create_voting;
};

struct t_mediator_command_response_get_voting_results : public t_mediator_command_response {
	t_mediator_command_response_get_voting_results() : t_mediator_command_response(t_mediator_cmd_type::e_get_voting_results){}
	std::string m_voting_name;
	std::string m_question;
	std::unordered_map<std::string, uint32_t> m_voting_results;
	size_t m_number_of_authorized_voters;
};

struct t_mediator_command_request_is_authorized : public t_mediator_command_request {
	t_mediator_command_request_is_authorized() : t_mediator_command_request(t_mediator_cmd_type::e_is_authorized){}
	t_public_key_type m_pk;
};

struct t_mediator_command_response_is_authorized : public t_mediator_command_response {
	t_mediator_command_response_is_authorized() : t_mediator_command_response(t_mediator_cmd_type::e_is_authorized){}
	std::vector<t_authorization_data> m_auth_data;
	bool m_is_adminsys;
};

struct t_mediator_command_request_get_all_active_votings_for_voter : public t_mediator_command_request {
	t_mediator_command_request_get_all_active_votings_for_voter() : t_mediator_command_request(t_mediator_cmd_type::e_get_all_active_votings_for_voter){}
	t_public_key_type m_voter_pk;
};

struct t_mediator_command_response_get_all_active_votings_for_voter : public t_mediator_command_response {
	t_mediator_command_response_get_all_active_votings_for_voter() : t_mediator_command_response(t_mediator_cmd_type::e_get_all_active_votings_for_voter){}
	std::vector<std::pair<t_hash_type, t_voting_metadata>> m_active_votings;
};

struct t_mediator_command_request_get_amount_on_pkh : public t_mediator_command_request {
	t_mediator_command_request_get_amount_on_pkh() : t_mediator_command_request(t_mediator_cmd_type::e_get_amount_on_pkh){}
	t_hash_type m_pkh;
};

struct t_mediator_command_response_get_amount_on_pkh : public t_mediator_command_response {
	t_mediator_command_response_get_amount_on_pkh() : t_mediator_command_response(t_mediator_cmd_type::e_get_amount_on_pkh){}
	uint32_t m_amount;
};

struct t_mediator_command_request_check_voter_voted : public t_mediator_command_request {
	t_mediator_command_request_check_voter_voted() : t_mediator_command_request(t_mediator_cmd_type::e_check_voter_voted){}
	t_public_key_type m_voter_pk;
	t_hash_type m_voting_id;
};

struct t_mediator_command_response_check_voter_voted : public t_mediator_command_response {
	t_mediator_command_response_check_voter_voted() : t_mediator_command_response(t_mediator_cmd_type::e_check_voter_voted){}
	bool m_voter_voted;
};

struct t_mediator_command_request_get_voter_auth_txid_for_voting : public t_mediator_command_request {
	t_mediator_command_request_get_voter_auth_txid_for_voting() : t_mediator_command_request(t_mediator_cmd_type::e_get_voter_auth_txid_for_voting){}
	t_public_key_type m_voter_pk;
	t_hash_type m_voting_id;
};

struct t_mediator_command_response_get_voter_auth_txid_for_voting : public t_mediator_command_response {
	t_mediator_command_response_get_voter_auth_txid_for_voting() : t_mediator_command_response(t_mediator_cmd_type::e_get_voter_auth_txid_for_voting){}
	t_hash_type m_txid;
};

struct t_mediator_command_request_get_voting_details : public t_mediator_command_request {
	t_mediator_command_request_get_voting_details() : t_mediator_command_request(t_mediator_cmd_type::e_get_voting_details){}
	t_hash_type m_voting_id;
};

struct t_mediator_command_response_get_voting_details : public t_mediator_command_response {
	t_mediator_command_response_get_voting_details() : t_mediator_command_response(t_mediator_cmd_type::e_get_voting_details){}
	t_voting_metadata m_voting_details;
};

struct t_mediator_command_request_get_source_txid_for_pkh : public t_mediator_command_request {
	t_mediator_command_request_get_source_txid_for_pkh() : t_mediator_command_request(t_mediator_cmd_type::e_get_source_txid_for_pkh){}
	t_hash_type m_pkh;
};

struct t_mediator_command_response_get_source_txid_for_pkh : public t_mediator_command_response {
	t_mediator_command_response_get_source_txid_for_pkh() : t_mediator_command_response(t_mediator_cmd_type::e_get_source_txid_for_pkh){}
	t_hash_type m_txid;
};

struct t_mediator_command_request_get_peers : public t_mediator_command_request {
	t_mediator_command_request_get_peers() : t_mediator_command_request(t_mediator_cmd_type::e_get_peers){}
};

struct t_mediator_command_response_get_peers : public t_mediator_command_response {
	t_mediator_command_response_get_peers() : t_mediator_command_response(t_mediator_cmd_type::e_get_peers){}
	std::vector<std::unique_ptr<c_peer_reference>> m_peers_tcp;
	std::vector<std::unique_ptr<c_peer_reference>> m_peers_tor;
};

struct t_mediator_command_request_get_metadata_from_tx : public t_mediator_command_request {
	t_mediator_command_request_get_metadata_from_tx() : t_mediator_command_request(t_mediator_cmd_type::e_get_metadata_from_tx){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_metadata_from_tx : public t_mediator_command_response {
	t_mediator_command_response_get_metadata_from_tx() : t_mediator_command_response(t_mediator_cmd_type::e_get_metadata_from_tx){}
	std::vector<unsigned char> m_metadata_from_tx;
};

struct t_mediator_command_request_get_last_block_time : public t_mediator_command_request {
	t_mediator_command_request_get_last_block_time() : t_mediator_command_request(t_mediator_cmd_type::e_get_last_block_time){}
};

struct t_mediator_command_response_get_last_block_time : public t_mediator_command_response {
	t_mediator_command_response_get_last_block_time() : t_mediator_command_response(t_mediator_cmd_type::e_get_last_block_time){}
	uint32_t m_block_time;
};

struct t_mediator_command_request_get_block_by_txid : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_txid() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_txid){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_block_by_txid : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_txid() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_txid){}
	c_block m_block;
};

struct t_mediator_command_request_get_all_vote_transactions : public t_mediator_command_request {
	t_mediator_command_request_get_all_vote_transactions() : t_mediator_command_request(t_mediator_cmd_type::e_get_all_vote_transactions){}
	t_hash_type m_voting_id;
};

struct t_mediator_command_response_get_all_vote_transactions : public t_mediator_command_response {
	t_mediator_command_response_get_all_vote_transactions() : t_mediator_command_response(t_mediator_cmd_type::e_get_all_vote_transactions){}
	std::vector<c_transaction> m_vote_transactions;
};

struct t_mediator_command_request_get_merkle_branch : public t_mediator_command_request {
	t_mediator_command_request_get_merkle_branch() : t_mediator_command_request(t_mediator_cmd_type::e_get_merkle_branch){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_merkle_branch : public t_mediator_command_response {
	t_mediator_command_response_get_merkle_branch() : t_mediator_command_response(t_mediator_cmd_type::e_get_merkle_branch){}
	std::vector<t_hash_type> m_merkle_branch;
	t_hash_type m_block_id;
};

struct t_mediator_command_request_get_voter_groups : public t_mediator_command_request {
	t_mediator_command_request_get_voter_groups() : t_mediator_command_request(t_mediator_cmd_type::e_get_voter_groups){}
	t_public_key_type m_voter_pk;
};

struct t_mediator_command_response_get_voter_groups : public t_mediator_command_response {
	t_mediator_command_response_get_voter_groups() : t_mediator_command_response(t_mediator_cmd_type::e_get_voter_groups){}
	std::vector<t_public_key_type> m_voter_groups;
};

struct t_mediator_command_request_get_number_of_all_voters: public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_voters() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_voters){}
};

struct t_mediator_command_response_get_number_of_all_voters: public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_voters() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_voters){}
	size_t m_number_of_all_voters;
};

struct t_mediator_command_request_get_number_of_miners: public t_mediator_command_request {
	t_mediator_command_request_get_number_of_miners() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_miners){}
};

struct t_mediator_command_response_get_number_of_miners: public t_mediator_command_response {
	t_mediator_command_response_get_number_of_miners() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_miners){}
	size_t m_number_of_miners;
};

struct t_mediator_command_request_get_number_of_all_votings : public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_votings() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_votings){}
};

struct t_mediator_command_response_get_number_of_all_votings : public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_votings() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_votings){}
	size_t m_number_of_all_votings;
};

struct t_mediator_command_request_get_number_of_all_inactive_votings : public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_inactive_votings() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_inactive_votings){}
};

struct t_mediator_command_response_get_number_of_all_inactive_votings : public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_inactive_votings() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_inactive_votings){}
	size_t m_number_of_all_inactive_votings;
};

struct t_mediator_command_request_get_number_of_all_added_votes : public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_added_votes() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_added_votes){}
};

struct t_mediator_command_response_get_number_of_all_added_votes : public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_added_votes() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_added_votes){}
	size_t m_number_of_all_added_votes;
};

struct t_mediator_command_request_get_number_of_all_transactions : public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_transactions() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_transactions){}
};

struct t_mediator_command_response_get_number_of_all_transactions : public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_transactions() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_transactions){}
	size_t m_number_of_all_transactions;
};

struct t_mediator_command_request_get_last_5_blocks : public t_mediator_command_request {
	t_mediator_command_request_get_last_5_blocks() : t_mediator_command_request(t_mediator_cmd_type::e_get_last_5_blocks){}
};

struct t_mediator_command_response_get_last_5_blocks : public t_mediator_command_response {
	t_mediator_command_response_get_last_5_blocks() : t_mediator_command_response(t_mediator_cmd_type::e_get_last_5_blocks){}
	std::vector<c_block_record> m_last_5_blocks;
};

struct t_mediator_command_request_get_last_5_transactions : public t_mediator_command_request {
	t_mediator_command_request_get_last_5_transactions() : t_mediator_command_request(t_mediator_cmd_type::e_get_last_5_transactions){}
};

struct t_mediator_command_response_get_last_5_transactions : public t_mediator_command_response {
	t_mediator_command_response_get_last_5_transactions() : t_mediator_command_response(t_mediator_cmd_type::e_get_last_5_transactions){}
	std::vector<c_transaction> m_last_5_transactions;
};

struct t_mediator_command_request_get_last_5_votings : public t_mediator_command_request {
	t_mediator_command_request_get_last_5_votings() : t_mediator_command_request(t_mediator_cmd_type::e_get_last_5_votings){}
};

struct t_mediator_command_response_get_last_5_votings : public t_mediator_command_response {
	t_mediator_command_response_get_last_5_votings() : t_mediator_command_response(t_mediator_cmd_type::e_get_last_5_votings){}
	std::vector<std::pair<t_hash_type, t_voting_metadata>> m_last_5_votings;
	std::vector<std::pair<t_hash_type, double>> m_voter_turnout;
	std::vector<std::pair<t_hash_type, bool>> m_is_finished;
	std::vector<t_hash_type> m_is_waiting;
};

struct t_mediator_command_request_get_block_by_id_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_id_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_id_without_txs_and_signs){}
	t_hash_type m_block_hash;
};

struct t_mediator_command_response_get_block_by_id_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_id_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_id_without_txs_and_signs){}
	c_block m_block;
};
struct t_mediator_command_request_get_block_by_height_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_height_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_height_without_txs_and_signs){}
	size_t m_height;
};

struct t_mediator_command_response_get_block_by_height_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_height_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_height_without_txs_and_signs){}
	c_block m_block;
};

struct t_mediator_command_request_get_block_by_txid_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_txid_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_txid_without_txs_and_signs){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_block_by_txid_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_txid_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_txid_without_txs_and_signs){}
	c_block m_block;
};

struct t_mediator_command_request_get_sorted_blocks_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_sorted_blocks_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_sorted_blocks){}
	size_t m_amount_of_blocks;
};

struct t_mediator_command_response_get_sorted_blocks_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_sorted_blocks_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_sorted_blocks){}
	std::vector<c_block_record> m_blocks;
};


struct t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_sorted_blocks_per_page){}
	size_t m_offset;
};

struct t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_sorted_blocks_per_page){}
	std::vector<c_block_record> m_blocks;
	size_t m_current_height;
};

struct t_mediator_command_request_get_latest_txs : public t_mediator_command_request {
	t_mediator_command_request_get_latest_txs() : t_mediator_command_request(t_mediator_cmd_type::e_get_latest_txs){}
	size_t m_amount_txs;
};

struct t_mediator_command_response_get_latest_txs : public t_mediator_command_response {
	t_mediator_command_response_get_latest_txs() : t_mediator_command_response(t_mediator_cmd_type::e_get_latest_txs){}
	std::vector<c_transaction> m_transactions;
};

struct t_mediator_command_request_get_txs_per_page : public t_mediator_command_request {
	t_mediator_command_request_get_txs_per_page() : t_mediator_command_request(t_mediator_cmd_type::e_get_txs_per_page){}
	size_t m_offset;
};

struct t_mediator_command_response_get_txs_per_page : public t_mediator_command_response {
	t_mediator_command_response_get_txs_per_page() : t_mediator_command_response(t_mediator_cmd_type::e_get_txs_per_page){}
	std::vector<c_transaction> m_transactions;
	size_t m_total_number_txs;
};

struct t_mediator_command_request_get_votings_by_name_or_id : public t_mediator_command_request {
	t_mediator_command_request_get_votings_by_name_or_id() : t_mediator_command_request(t_mediator_cmd_type::e_get_votings_by_name_or_id){}
	std::string m_name_or_voting_id;
	size_t m_offset;
};

struct t_mediator_command_response_get_votings_by_name_or_id : public t_mediator_command_response {
	t_mediator_command_response_get_votings_by_name_or_id() : t_mediator_command_response(t_mediator_cmd_type::e_get_votings_by_name_or_id){}
	std::vector<std::pair<t_hash_type, t_voting_metadata>> m_votings;
	std::vector<std::pair<t_hash_type, std::unordered_map<std::string, uint32_t>> >m_votings_results;
	std::vector<std::pair<t_hash_type, double>> m_voter_turnout;
	std::vector<std::pair<t_hash_type, bool>> m_is_finished;
	std::vector<t_hash_type> m_is_waiting;
	size_t m_total_number_votings;
};

struct t_mediator_command_request_get_latest_votings : public t_mediator_command_request {
	t_mediator_command_request_get_latest_votings() : t_mediator_command_request(t_mediator_cmd_type::e_get_latest_votings){}
	size_t m_amount_votings;
};

struct t_mediator_command_response_get_latest_votings : public t_mediator_command_response {
	t_mediator_command_response_get_latest_votings() : t_mediator_command_response(t_mediator_cmd_type::e_get_latest_votings){}
	std::vector<std::pair<t_hash_type, t_voting_metadata>> m_latest_votings;
	std::vector<std::pair<t_hash_type, double>> m_voter_turnout;
	std::vector<std::pair<t_hash_type, bool>> m_is_finished;
	std::vector<t_hash_type> m_is_waiting;
};

struct t_mediator_command_request_get_votings_per_page : public t_mediator_command_request {
	t_mediator_command_request_get_votings_per_page() : t_mediator_command_request(t_mediator_cmd_type::e_get_votings_per_page){}
	size_t m_offset;
};

struct t_mediator_command_response_get_votings_per_page : public t_mediator_command_response {
	t_mediator_command_response_get_votings_per_page() : t_mediator_command_response(t_mediator_cmd_type::e_get_votings_per_page){}
	std::vector<std::pair<t_hash_type, t_voting_metadata>> m_votings;
	std::vector<std::pair<t_hash_type, double>> m_voter_turnout;
	std::vector<std::pair<t_hash_type, bool>> m_is_finished;
	std::vector<t_hash_type> m_is_waiting;
	size_t m_total_number_votings;
};

struct t_mediator_command_request_get_txs_from_block_per_page : public t_mediator_command_request {
	t_mediator_command_request_get_txs_from_block_per_page() : t_mediator_command_request(t_mediator_cmd_type::e_get_txs_from_block_per_page){}
	size_t m_offset;
	t_hash_type m_block_id;
};

struct t_mediator_command_response_get_txs_from_block_per_page : public t_mediator_command_response {
	t_mediator_command_response_get_txs_from_block_per_page() : t_mediator_command_response(t_mediator_cmd_type::e_get_txs_from_block_per_page){}
	std::vector<c_transaction> m_transactions;
	size_t m_number_txs;
};

struct t_mediator_command_request_get_block_signatures_and_pks_miners_per_page : public t_mediator_command_request {
	t_mediator_command_request_get_block_signatures_and_pks_miners_per_page() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_signatures_and_pk_miners_per_page){}
	size_t m_offset;
	t_hash_type m_block_id;
};

struct t_mediator_command_response_get_block_signatures_and_pks_miners_per_page : public t_mediator_command_response {
	t_mediator_command_response_get_block_signatures_and_pks_miners_per_page() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_signatures_and_pk_miners_per_page){}
	std::vector<std::pair<t_signature_type, t_public_key_type>> m_signatures_and_pks;
	size_t m_number_signatures;
};

struct t_mediator_command_request_get_number_of_all_active_votings : public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_active_votings() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_active_votings){}
};

struct t_mediator_command_response_get_number_of_all_active_votings : public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_active_votings() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_active_votings){}
	size_t m_number_of_all_active_votings;
};

struct t_mediator_command_request_get_number_of_all_finished_votings : public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_finished_votings() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_finished_votings){}
};

struct t_mediator_command_response_get_number_of_all_finished_votings : public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_finished_votings() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_finished_votings){}
	size_t m_number_of_all_finished_votings;
};

struct t_mediator_command_request_get_voting_by_id : public t_mediator_command_request {
	t_mediator_command_request_get_voting_by_id() : t_mediator_command_request(t_mediator_cmd_type::e_get_voting_by_id){}
	t_hash_type m_voting_id;
};

struct t_mediator_command_response_get_voting_by_id : public t_mediator_command_response {
	t_mediator_command_response_get_voting_by_id() : t_mediator_command_response(t_mediator_cmd_type::e_get_voting_by_id){}
	t_voting_metadata m_voting_metadata;
	unsigned char m_voting_status;
	std::unordered_map<std::string, uint32_t> m_voting_results;
	double m_voter_turnout;
};

struct t_mediator_command_request_is_blockchain_synchronized : public t_mediator_command_request {
	t_mediator_command_request_is_blockchain_synchronized() : t_mediator_command_request(t_mediator_cmd_type::e_is_blockchain_synchronized){}
};

struct t_mediator_command_response_is_blockchain_synchronized : public t_mediator_command_response {
	t_mediator_command_response_is_blockchain_synchronized() : t_mediator_command_response(t_mediator_cmd_type::e_is_blockchain_synchronized){}
	bool m_is_blockchain_synchronized = false;
};

struct t_mediator_command_request_get_all_finished_votings_for_voter : public t_mediator_command_request {
	t_mediator_command_request_get_all_finished_votings_for_voter() : t_mediator_command_request(t_mediator_cmd_type::e_get_all_finished_votings_for_voter){}
	t_public_key_type m_voter_pk;
};

struct t_mediator_command_response_get_all_finished_votings_for_voter : public t_mediator_command_response {
	t_mediator_command_response_get_all_finished_votings_for_voter() : t_mediator_command_response(t_mediator_cmd_type::e_get_all_finished_votings_for_voter){}
	std::vector<std::pair<t_hash_type, t_voting_metadata>> m_finished_votings;
};

struct t_mediator_command_request_block_exists : public t_mediator_command_request {
	t_mediator_command_request_block_exists() : t_mediator_command_request(t_mediator_cmd_type::e_block_exists){}
	t_hash_type block_id;
};
struct t_mediator_command_response_block_exists : public t_mediator_command_response {
	t_mediator_command_response_block_exists() : t_mediator_command_response(t_mediator_cmd_type::e_block_exists){}
	bool m_block_exists;
};
#endif // MEDIATOR_COMMANDS_HPP
