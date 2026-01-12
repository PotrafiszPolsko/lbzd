#ifndef MEDIATOR_COMMANDS_HPP
#define MEDIATOR_COMMANDS_HPP

#include "block.hpp"
#include "transaction.hpp"
#include "wallet.hpp"
#include "blockchain.hpp"
#include "shared_mutex"
#include "params.hpp"
#include "peer_reference.hpp"

enum class t_mediator_cmd_type {
	e_get_tx = 0,
	e_get_block_by_height = 1,
	e_get_block_by_id = 2,
	e_get_last_block_hash = 3,
	e_add_new_block = 4,
	e_add_new_transaction = 5,
	e_broadcast_block = 6,
	e_broadcast_transaction = 7,
	e_get_mempool_size = 8,
	e_get_pk_and_sign = 9,
	e_get_mempool_transactions = 10,
	e_get_blockchain_ref = 11, // for simulation only
	e_get_block_by_id_proto = 12,
	e_get_headers_proto = 13,
	e_is_organizer_pk = 14,
	e_authorize_organizer_by_admin = 15,
	e_authorize_miner_by_admin = 16,
	e_sign_message_by_main_identity = 17,
	e_get_mnemonic_sentence = 18,
	e_set_key_from_mnemonic = 19,
	e_get_height = 20,
	e_add_transaction_to_mempool = 21,
	e_is_authorized = 22,
	e_get_pk = 23,
	e_sign_tx_by_main_identity = 24,
	e_get_peers = 25,
	e_get_metadata_from_tx = 26,
	e_add_voting_protocol = 27,
	e_get_last_block_time = 28,
	e_get_block_by_txid = 29,
	e_get_merkle_branch = 30,
	e_get_number_of_miners = 31,
	e_get_number_of_all_transactions = 32,
	e_get_block_by_id_without_txs_and_signs = 33,
	e_get_block_by_height_without_txs_and_signs = 34,
	e_get_block_by_txid_without_txs_and_signs = 35,
	e_get_sorted_blocks = 36,
	e_get_sorted_blocks_per_page = 37,
	e_get_latest_txs = 38,
	e_get_txs_per_page = 39,
	e_get_txs_from_block_per_page = 40,
	e_get_block_signatures_and_pk_miners_per_page = 41,
	e_is_blockchain_synchronized = 42,
	e_block_exists = 43
};

///////////////////////////////////////////////

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

///////////////////////////////////////////////

struct t_mediator_command_request_get_tx : public t_mediator_command_request {
	t_mediator_command_request_get_tx() : t_mediator_command_request(t_mediator_cmd_type::e_get_tx){}
	t_hash_type m_txid;
};


struct t_mediator_command_response_get_tx : public t_mediator_command_response {
	t_mediator_command_response_get_tx() : t_mediator_command_response(t_mediator_cmd_type::e_get_tx){}
	c_transaction m_transaction;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_block_by_height : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_height() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_height){}
	size_t m_height;
};

struct t_mediator_command_response_get_block_by_height : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_height() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_height){}
	c_block m_block;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_block_by_id : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_id() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_id){}
	t_hash_type m_block_hash;
};

struct t_mediator_command_response_get_block_by_id : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_id() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_id){}
	c_block m_block;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_last_block_hash : public t_mediator_command_request {
	t_mediator_command_request_get_last_block_hash() : t_mediator_command_request(t_mediator_cmd_type::e_get_last_block_hash){}
};

struct t_mediator_command_response_get_last_block_hash : public t_mediator_command_response {
	t_mediator_command_response_get_last_block_hash() : t_mediator_command_response(t_mediator_cmd_type::e_get_last_block_hash){}
	t_hash_type m_last_block_hash;
};

///////////////////////////////////////////////

struct t_mediator_command_request_add_new_block : public t_mediator_command_request {
	t_mediator_command_request_add_new_block() : t_mediator_command_request(t_mediator_cmd_type::e_add_new_block){}
	c_block m_block;
};

struct t_mediator_command_response_add_new_block : public t_mediator_command_response {
	t_mediator_command_response_add_new_block() : t_mediator_command_response(t_mediator_cmd_type::e_add_new_block){}
	bool m_is_blockchain_synchronized = false;
	bool m_is_block_exists = false;
};


///////////////////////////////////////////////

// add to blockchain module
struct t_mediator_command_request_add_new_transaction : public t_mediator_command_request {
	t_mediator_command_request_add_new_transaction() : t_mediator_command_request(t_mediator_cmd_type::e_add_new_transaction){}
	c_transaction m_transaction;
};

// add to blockchain module
struct t_mediator_command_response_add_new_transaction : public t_mediator_command_response {
	t_mediator_command_response_add_new_transaction() : t_mediator_command_response(t_mediator_cmd_type::e_add_new_transaction){}
	bool m_tx_added_to_mempool;
};

///////////////////////////////////////////////

struct t_mediator_command_request_broadcast_block : public t_mediator_command_request {
	t_mediator_command_request_broadcast_block() : t_mediator_command_request(t_mediator_cmd_type::e_broadcast_block){}
	c_block m_block;
};

struct t_mediator_command_response_broadcast_block : public t_mediator_command_response {
	t_mediator_command_response_broadcast_block() : t_mediator_command_response(t_mediator_cmd_type::e_broadcast_block){}
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_pk_and_sign : public t_mediator_command_request {
	t_mediator_command_request_get_pk_and_sign() : t_mediator_command_request(t_mediator_cmd_type::e_get_pk_and_sign){}
	std::string m_msg_to_sign;
};

struct t_mediator_command_response_get_pk_and_sign : public t_mediator_command_response {
	t_mediator_command_response_get_pk_and_sign() : t_mediator_command_response(t_mediator_cmd_type::e_get_pk_and_sign){}
	t_public_key_type m_pk;
	t_signature_type m_sign;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_pk : public t_mediator_command_request {
	t_mediator_command_request_get_pk() : t_mediator_command_request(t_mediator_cmd_type::e_get_pk){}
};

struct t_mediator_command_response_get_pk : public t_mediator_command_response {
	t_mediator_command_response_get_pk() : t_mediator_command_response(t_mediator_cmd_type::e_get_pk){}
	t_public_key_type m_pk;
};
///////////////////////////////////////////////

struct t_mediator_command_request_broadcast_transaction : public t_mediator_command_request {
	t_mediator_command_request_broadcast_transaction() : t_mediator_command_request(t_mediator_cmd_type::e_broadcast_transaction){}
	c_transaction m_transaction;
};

struct t_mediator_command_response_broadcast_transaction : public t_mediator_command_response {
	t_mediator_command_response_broadcast_transaction() : t_mediator_command_response(t_mediator_cmd_type::e_broadcast_transaction){}
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_mempool_size : public t_mediator_command_request {
	t_mediator_command_request_get_mempool_size() : t_mediator_command_request(t_mediator_cmd_type::e_get_mempool_size){}
};

struct t_mediator_command_response_get_mempool_size : public t_mediator_command_response {
	t_mediator_command_response_get_mempool_size() : t_mediator_command_response(t_mediator_cmd_type::e_get_mempool_size){}
	size_t m_number_of_transactions;
	// size_t m_mempool_size_in_bytes;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_mempool_transactions : public t_mediator_command_request {
	t_mediator_command_request_get_mempool_transactions() : t_mediator_command_request(t_mediator_cmd_type::e_get_mempool_transactions){}
};

struct t_mediator_command_response_get_mempool_transactions : public t_mediator_command_response {
	t_mediator_command_response_get_mempool_transactions() : t_mediator_command_response(t_mediator_cmd_type::e_get_mempool_transactions){}
	std::vector<c_transaction> m_transactions;
};

///////////////////////////////////////////////

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

///////////////////////////////////////////////

struct t_mediator_command_request_get_block_by_id_proto : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_id_proto() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_id_proto){}
	t_hash_type m_block_hash;
};

struct t_mediator_command_response_get_block_by_id_proto : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_id_proto() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_id_proto){}
	proto::block m_block_proto;
};

///////////////////////////////////////////////

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

//////////////////////////////////////////////

struct t_mediator_command_request_is_organizer_pk : public t_mediator_command_request {
	t_mediator_command_request_is_organizer_pk() : t_mediator_command_request(t_mediator_cmd_type::e_is_organizer_pk){}
	t_public_key_type m_pk;
};

struct t_mediator_command_response_is_organizer_pk : public t_mediator_command_response {
	t_mediator_command_response_is_organizer_pk() : t_mediator_command_response(t_mediator_cmd_type::e_is_organizer_pk){}
	bool m_is_organizer_pk;
};

//////////////////////////////////////////////

struct t_mediator_command_request_authorize_organizer_by_admin : public t_mediator_command_request {
	t_mediator_command_request_authorize_organizer_by_admin() : t_mediator_command_request(t_mediator_cmd_type::e_authorize_organizer_by_admin){}
	t_public_key_type m_organizer_pk;
};

struct t_mediator_command_response_authorize_organizer_by_admin : public t_mediator_command_response {
	t_mediator_command_response_authorize_organizer_by_admin() : t_mediator_command_response(t_mediator_cmd_type::e_authorize_organizer_by_admin){}
	t_hash_type m_txid_auth_organizer;
};

///////////////////////////////////////////////

struct t_mediator_command_request_authorize_miner_by_admin : public t_mediator_command_request {
	t_mediator_command_request_authorize_miner_by_admin() : t_mediator_command_request(t_mediator_cmd_type::e_authorize_miner_by_admin){}
	t_public_key_type m_miner_pk;
};

struct t_mediator_command_response_authorize_miner_by_admin : public t_mediator_command_response {
	t_mediator_command_response_authorize_miner_by_admin() : t_mediator_command_response(t_mediator_cmd_type::e_authorize_miner_by_admin){}
	t_hash_type m_txid_auth_miner;
};

///////////////////////////////////////////////

struct t_mediator_command_request_sign_message_by_main_identity : public t_mediator_command_request {
	t_mediator_command_request_sign_message_by_main_identity() : t_mediator_command_request(t_mediator_cmd_type::e_sign_message_by_main_identity){}
	std::string_view m_msg;
};

struct t_mediator_command_response_sign_message_by_main_identity : public t_mediator_command_response {
	t_mediator_command_response_sign_message_by_main_identity() : t_mediator_command_response(t_mediator_cmd_type::e_sign_message_by_main_identity){}
	t_signature_type m_sign;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_mnemonic_sentence : public t_mediator_command_request {
	t_mediator_command_request_get_mnemonic_sentence() : t_mediator_command_request(t_mediator_cmd_type::e_get_mnemonic_sentence){}
};

struct t_mediator_command_response_get_mnemonic_sentence : public t_mediator_command_response {
	t_mediator_command_response_get_mnemonic_sentence() : t_mediator_command_response(t_mediator_cmd_type::e_get_mnemonic_sentence){}
	std::array<std::string, n_seedparams::seed_number_of_words> m_seed_words;
};

///////////////////////////////////////////////

struct t_mediator_command_request_set_key_from_mnemonic : public t_mediator_command_request {
	t_mediator_command_request_set_key_from_mnemonic() : t_mediator_command_request(t_mediator_cmd_type::e_set_key_from_mnemonic){}
	std::array<std::string, n_seedparams::seed_number_of_words> m_seed_words;
};

struct t_mediator_command_response_set_key_from_mnemonic : public t_mediator_command_response {
	t_mediator_command_response_set_key_from_mnemonic() : t_mediator_command_response(t_mediator_cmd_type::e_set_key_from_mnemonic){}
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_height : public t_mediator_command_request {
	t_mediator_command_request_get_height() : t_mediator_command_request(t_mediator_cmd_type::e_get_height){}
};

struct t_mediator_command_response_get_height : public t_mediator_command_response {
	t_mediator_command_response_get_height() : t_mediator_command_response(t_mediator_cmd_type::e_get_height){}
	size_t m_height;
};

///////////////////////////////////////////////

struct t_mediator_command_request_add_transaction_to_mempool : public t_mediator_command_request {
	t_mediator_command_request_add_transaction_to_mempool() : t_mediator_command_request(t_mediator_cmd_type::e_add_transaction_to_mempool){}
	c_transaction m_tx;
};

struct t_mediator_command_response_add_transaction_to_mempool : public t_mediator_command_response {
	t_mediator_command_response_add_transaction_to_mempool() : t_mediator_command_response(t_mediator_cmd_type::e_add_transaction_to_mempool){}
};

///////////////////////////////////////////////

struct t_mediator_command_request_is_authorized : public t_mediator_command_request {
	t_mediator_command_request_is_authorized() : t_mediator_command_request(t_mediator_cmd_type::e_is_authorized){}
	t_public_key_type m_pk;
};

struct t_mediator_command_response_is_authorized : public t_mediator_command_response {
	t_mediator_command_response_is_authorized() : t_mediator_command_response(t_mediator_cmd_type::e_is_authorized){}
	bool m_is_adminsys;
	bool m_is_organizer;
	bool m_is_miner;
	t_hash_type m_txid_auth;
};

///////////////////////////////////////////////

struct t_mediator_command_request_sign_tx_by_main_identity : public t_mediator_command_request {
	t_mediator_command_request_sign_tx_by_main_identity() : t_mediator_command_request(t_mediator_cmd_type::e_sign_tx_by_main_identity){}
	c_transaction m_transaction_to_sign;
};

struct t_mediator_command_response_sign_tx_by_main_identity : public t_mediator_command_response {
	t_mediator_command_response_sign_tx_by_main_identity() : t_mediator_command_response(t_mediator_cmd_type::e_sign_tx_by_main_identity){}
	t_signature_type m_transaction_signature;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_peers : public t_mediator_command_request {
	t_mediator_command_request_get_peers() : t_mediator_command_request(t_mediator_cmd_type::e_get_peers){}
};

struct t_mediator_command_response_get_peers : public t_mediator_command_response {
	t_mediator_command_response_get_peers() : t_mediator_command_response(t_mediator_cmd_type::e_get_peers){}
	std::vector<std::unique_ptr<c_peer_reference>> m_peers_tcp;
	std::vector<std::unique_ptr<c_peer_reference>> m_peers_tor;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_metadata_from_tx : public t_mediator_command_request {
	t_mediator_command_request_get_metadata_from_tx() : t_mediator_command_request(t_mediator_cmd_type::e_get_metadata_from_tx){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_metadata_from_tx : public t_mediator_command_response {
	t_mediator_command_response_get_metadata_from_tx() : t_mediator_command_response(t_mediator_cmd_type::e_get_metadata_from_tx){}
	std::vector<unsigned char> m_metadata_from_tx;
};

//////////////////////////////////////////////

struct t_mediator_command_request_add_voting_protocol : public t_mediator_command_request {
	t_mediator_command_request_add_voting_protocol() : t_mediator_command_request(t_mediator_cmd_type::e_add_voting_protocol){}
	std::vector<unsigned char> m_voting_protocol;
};

struct t_mediator_command_response_add_voting_protocol : public t_mediator_command_response {
	t_mediator_command_response_add_voting_protocol() : t_mediator_command_response(t_mediator_cmd_type::e_add_voting_protocol){}
	t_hash_type m_txid;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_last_block_time : public t_mediator_command_request {
	t_mediator_command_request_get_last_block_time() : t_mediator_command_request(t_mediator_cmd_type::e_get_last_block_time){}
};

struct t_mediator_command_response_get_last_block_time : public t_mediator_command_response {
	t_mediator_command_response_get_last_block_time() : t_mediator_command_response(t_mediator_cmd_type::e_get_last_block_time){}
	uint32_t m_block_time;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_block_by_txid : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_txid() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_txid){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_block_by_txid : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_txid() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_txid){}
	c_block m_block;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_merkle_branch : public t_mediator_command_request {
	t_mediator_command_request_get_merkle_branch() : t_mediator_command_request(t_mediator_cmd_type::e_get_merkle_branch){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_merkle_branch : public t_mediator_command_response {
	t_mediator_command_response_get_merkle_branch() : t_mediator_command_response(t_mediator_cmd_type::e_get_merkle_branch){}
	std::vector<t_hash_type> m_merkle_branch;
	t_hash_type m_block_id;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_number_of_miners: public t_mediator_command_request {
	t_mediator_command_request_get_number_of_miners() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_miners){}
};

struct t_mediator_command_response_get_number_of_miners: public t_mediator_command_response {
	t_mediator_command_response_get_number_of_miners() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_miners){}
	size_t m_number_of_miners;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_number_of_all_transactions : public t_mediator_command_request {
	t_mediator_command_request_get_number_of_all_transactions() : t_mediator_command_request(t_mediator_cmd_type::e_get_number_of_all_transactions){}
};

struct t_mediator_command_response_get_number_of_all_transactions : public t_mediator_command_response {
	t_mediator_command_response_get_number_of_all_transactions() : t_mediator_command_response(t_mediator_cmd_type::e_get_number_of_all_transactions){}
	size_t m_number_of_all_transactions;
};

//////////////////////////////////////////////

struct t_mediator_command_request_get_block_by_id_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_id_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_id_without_txs_and_signs){}
	t_hash_type m_block_hash;
};

struct t_mediator_command_response_get_block_by_id_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_id_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_id_without_txs_and_signs){}
	c_block m_block;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_block_by_height_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_height_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_height_without_txs_and_signs){}
	size_t m_height;
};

struct t_mediator_command_response_get_block_by_height_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_height_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_height_without_txs_and_signs){}
	c_block m_block;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_block_by_txid_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_block_by_txid_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_block_by_txid_without_txs_and_signs){}
	t_hash_type m_txid;
};

struct t_mediator_command_response_get_block_by_txid_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_block_by_txid_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_block_by_txid_without_txs_and_signs){}
	c_block m_block;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_sorted_blocks_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_sorted_blocks_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_sorted_blocks){}
	size_t m_amount_of_blocks;
};

struct t_mediator_command_response_get_sorted_blocks_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_sorted_blocks_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_sorted_blocks){}
	std::vector<c_block_record> m_blocks;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs : public t_mediator_command_request {
	t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs() : t_mediator_command_request(t_mediator_cmd_type::e_get_sorted_blocks_per_page){}
	size_t m_offset;
};

struct t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs : public t_mediator_command_response {
	t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs() : t_mediator_command_response(t_mediator_cmd_type::e_get_sorted_blocks_per_page){}
	std::vector<c_block_record> m_blocks;
	size_t m_current_height;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_latest_txs : public t_mediator_command_request {
	t_mediator_command_request_get_latest_txs() : t_mediator_command_request(t_mediator_cmd_type::e_get_latest_txs){}
	size_t m_amount_txs;
};

struct t_mediator_command_response_get_latest_txs : public t_mediator_command_response {
	t_mediator_command_response_get_latest_txs() : t_mediator_command_response(t_mediator_cmd_type::e_get_latest_txs){}
	std::vector<c_transaction> m_transactions;
};

///////////////////////////////////////////////

struct t_mediator_command_request_get_txs_per_page : public t_mediator_command_request {
	t_mediator_command_request_get_txs_per_page() : t_mediator_command_request(t_mediator_cmd_type::e_get_txs_per_page){}
	size_t m_offset;
};

struct t_mediator_command_response_get_txs_per_page : public t_mediator_command_response {
	t_mediator_command_response_get_txs_per_page() : t_mediator_command_response(t_mediator_cmd_type::e_get_txs_per_page){}
	std::vector<c_transaction> m_transactions;
	size_t m_total_number_txs;
};

///////////////////////////////////////////////

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

///////////////////////////////////////////////

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

///////////////////////////////////////////////

struct t_mediator_command_request_is_blockchain_synchronized : public t_mediator_command_request {
	t_mediator_command_request_is_blockchain_synchronized() : t_mediator_command_request(t_mediator_cmd_type::e_is_blockchain_synchronized){}
};

struct t_mediator_command_response_is_blockchain_synchronized : public t_mediator_command_response {
	t_mediator_command_response_is_blockchain_synchronized() : t_mediator_command_response(t_mediator_cmd_type::e_is_blockchain_synchronized){}
	bool m_is_blockchain_synchronized = false;
};

///////////////////////////////////////////////

struct t_mediator_command_request_block_exists : public t_mediator_command_request {
	t_mediator_command_request_block_exists() : t_mediator_command_request(t_mediator_cmd_type::e_block_exists){}
	t_hash_type m_block_id;
};
struct t_mediator_command_response_block_exists : public t_mediator_command_response {
	t_mediator_command_response_block_exists() : t_mediator_command_response(t_mediator_cmd_type::e_block_exists){}
	bool m_block_exists;
};

#endif // MEDIATOR_COMMANDS_HPP
