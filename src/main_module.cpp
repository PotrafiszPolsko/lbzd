#include "main_module.hpp"
#include "params.hpp"
#include "logger.hpp"

std::unique_ptr<t_mediator_command_response> c_main_module::notify(const t_mediator_command_request & request) {
	std::unique_ptr<t_mediator_command_response> response;
	switch (request.m_type) {
		case t_mediator_cmd_type::e_add_new_block:
		{
			const auto & add_new_block_request = dynamic_cast<const t_mediator_command_request_add_new_block&>(request);
			const auto & block = add_new_block_request.m_block;
			response = std::make_unique<t_mediator_command_response_add_new_block>();
			auto & response_add_new_block = dynamic_cast<t_mediator_command_response_add_new_block&>(*response);
			m_blockchain_module->add_new_block(block);
			response_add_new_block.m_is_blockchain_synchronized = m_blockchain_module->is_blockchain_synchronized();
			response_add_new_block.m_is_block_exists = m_blockchain_module->block_exists(block.m_header.m_actual_hash);
			break;
		}
		case t_mediator_cmd_type::e_add_new_transaction:
		{
			const auto & add_new_tx_request = dynamic_cast<const t_mediator_command_request_add_new_transaction &>(request);
			const auto & tx = add_new_tx_request.m_transaction;
			
			const auto tx_added_to_mempool = m_blockchain_module->add_new_transaction(tx);
			response = std::make_unique<t_mediator_command_response_add_new_transaction>();
			auto & response_new_tx = dynamic_cast<t_mediator_command_response_add_new_transaction &>(*response);
			response_new_tx.m_tx_added_to_mempool = tx_added_to_mempool;
			
			if (tx_added_to_mempool) break; // full transaction added to mempool
			else throw std::runtime_error("transaction is not added to mempool");
			break;
		}
		case t_mediator_cmd_type::e_authorize_organizer_by_admin:
		{
			const auto & request_organizer_pk = dynamic_cast<const t_mediator_command_request_authorize_organizer_by_admin&>(request);
			const auto pk_admin = m_wallet_module->get_main_pk();
			if(!n_blockchainparams::is_pk_adminsys(pk_admin)) throw std::invalid_argument("Bad adminsys public key");
			auto auth_tx = m_blockchain_module->authorize_organizer_by_adminsys(request_organizer_pk.m_organizer_pk, pk_admin);
			const auto tx_added = m_blockchain_module->add_new_transaction(auth_tx);
			if (tx_added) m_p2p_module->broadcast_transaction(auth_tx);
			response = std::make_unique<t_mediator_command_response_authorize_organizer_by_admin>();
			auto & response_authorize_organizer = dynamic_cast<t_mediator_command_response_authorize_organizer_by_admin&>(*response);
			response_authorize_organizer.m_txid_auth_organizer = auth_tx.m_txid;
			break;
		}
		case t_mediator_cmd_type::e_authorize_miner_by_admin:
		{
			const auto & request_miner_pk = dynamic_cast<const t_mediator_command_request_authorize_miner_by_admin&>(request);
			const auto pk_admin = m_wallet_module->get_main_pk();
			if(!n_blockchainparams::is_pk_adminsys(pk_admin)) throw std::invalid_argument("Bad adminsys public key");
			auto auth_tx = m_blockchain_module->authorize_miner_by_adminsys(request_miner_pk.m_miner_pk, pk_admin);
			const auto tx_added = m_blockchain_module->add_new_transaction(auth_tx);
			if (tx_added) m_p2p_module->broadcast_transaction(auth_tx);
			response = std::make_unique<t_mediator_command_response_authorize_miner_by_admin>();
			auto & response_authorize_miner = dynamic_cast<t_mediator_command_response_authorize_miner_by_admin&>(*response);
			response_authorize_miner.m_txid_auth_miner = auth_tx.m_txid;
			break;
		}	
		case t_mediator_cmd_type::e_add_transaction_to_mempool:
		{
			const auto &request_get_tx = dynamic_cast<const t_mediator_command_request_add_transaction_to_mempool&>(request);
			const auto &tx = request_get_tx.m_tx;
			if(m_blockchain_module->is_transaction_in_blockchain(tx.m_txid)) throw std::invalid_argument("this transaction is in blockchain");
			if(!m_blockchain_module->add_new_transaction(tx)) throw std::invalid_argument("this transaction is in mempool");
			m_p2p_module->broadcast_transaction(tx);
			response = std::make_unique<t_mediator_command_response_add_transaction_to_mempool>();
			break;
		}
		case t_mediator_cmd_type::e_broadcast_block:
		{
			const auto & broadcast_block_request = dynamic_cast<const t_mediator_command_request_broadcast_block&>(request);
			const auto & block = broadcast_block_request.m_block;
			m_p2p_module->broadcast_block(block);
			response = std::make_unique<t_mediator_command_response_broadcast_block>();
			break;
		}
		case t_mediator_cmd_type::e_broadcast_transaction:
		{
			const auto & broadcast_transaction_request = dynamic_cast<const t_mediator_command_request_broadcast_transaction&>(request);
			const auto & transaction = broadcast_transaction_request.m_transaction;
			m_p2p_module->broadcast_transaction(transaction);
			response = std::make_unique<t_mediator_command_response_broadcast_transaction>();
			break;
		}
		case t_mediator_cmd_type::e_set_key_from_mnemonic:
		{
			const auto & request_set_key_from_mnemonic = dynamic_cast<const t_mediator_command_request_set_key_from_mnemonic&>(request);
			m_wallet_module->generate_seed_from_words(request_set_key_from_mnemonic.m_seed_words);
			response = std::make_unique<t_mediator_command_response_set_key_from_mnemonic>();
			break;
		}
		case t_mediator_cmd_type::e_add_voting_protocol:
		{
			const auto my_pk = m_wallet_module->get_main_pk();
			const auto is_pk_organizer = m_blockchain_module->is_pk_organizer(my_pk);
			if (!is_pk_organizer) throw std::runtime_error("Organizer permissions needed");
			const auto & request_add_another_voting_protocol = dynamic_cast<const t_mediator_command_request_add_voting_protocol&>(request);
			const auto & voting_protocol = request_add_another_voting_protocol.m_voting_protocol;
			const auto tx = m_blockchain_module->add_voting_protocol(voting_protocol, my_pk);
			if(m_blockchain_module->is_transaction_in_blockchain(tx.m_txid)) throw std::invalid_argument("this transaction is in blockchain");
			if(!m_blockchain_module->add_new_transaction(tx)) throw std::invalid_argument("this transaction is in mempool");
			m_p2p_module->broadcast_transaction(tx);
			response = std::make_unique<t_mediator_command_response_add_voting_protocol>();
			auto & response_add_voting_protocol = dynamic_cast<t_mediator_command_response_add_voting_protocol&>(*response);
			response_add_voting_protocol.m_txid = tx.m_txid;
			break;
		}
		default:
			break;
	}
	if (response == nullptr) response = std::as_const(*this).notify(request);
	assert(response != nullptr);
	return response;
}

std::unique_ptr<t_mediator_command_response> c_main_module::notify(const t_mediator_command_request & request) const {
	std::unique_ptr<t_mediator_command_response> response;
	switch (request.m_type) {
		case t_mediator_cmd_type::e_get_tx:
		{
			const auto & request_get_tx = dynamic_cast<const t_mediator_command_request_get_tx&>(request);
			auto tx = m_blockchain_module->get_transaction(request_get_tx.m_txid);
			response = std::make_unique<t_mediator_command_response_get_tx>();
			auto & response_get_tx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
			response_get_tx.m_transaction = std::move(tx);
			break;
		}
		case t_mediator_cmd_type::e_get_block_by_height:
		{
			const auto & request_get_block = dynamic_cast<const t_mediator_command_request_get_block_by_height&>(request);
			auto block = m_blockchain_module->get_block_at_height(request_get_block.m_height);
			response = std::make_unique<t_mediator_command_response_get_block_by_height>();
			auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_height&>(*response);
			response_get_block.m_block = std::move(block);
			break;
		}
		case t_mediator_cmd_type::e_get_block_by_id:
		{
			const auto & request_get_block = dynamic_cast<const t_mediator_command_request_get_block_by_id&>(request);
			auto block = m_blockchain_module->get_block_at_hash(request_get_block.m_block_hash);
			response = std::make_unique<t_mediator_command_response_get_block_by_id>();
			auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_id&>(*response);
			response_get_block.m_block = std::move(block);
			break;
		}
		case t_mediator_cmd_type::e_get_last_block_hash:
		{
			response = std::make_unique<t_mediator_command_response_get_last_block_hash>();
			auto & response_get_last_block_hash = dynamic_cast<t_mediator_command_response_get_last_block_hash&>(*response);
			response_get_last_block_hash.m_last_block_hash = m_blockchain_module->get_last_block_hash();
			break;
		}
		case t_mediator_cmd_type::e_get_mempool_size:
		{
			response = std::make_unique<t_mediator_command_response_get_mempool_size>();
			auto & response_as_get_mempool_size = dynamic_cast<t_mediator_command_response_get_mempool_size&>(*response);
			response_as_get_mempool_size.m_number_of_transactions = m_blockchain_module->get_number_of_mempool_transactions();
			break;
		}
		case t_mediator_cmd_type::e_get_pk:
		{
			const auto pk = m_wallet_module->get_main_pk();
			response = std::make_unique<t_mediator_command_response_get_pk>();
			auto & response_get_pk = dynamic_cast<t_mediator_command_response_get_pk&>(*response);
			response_get_pk.m_pk = pk;
			break;
		}
		case t_mediator_cmd_type::e_get_mempool_transactions:
		{
			response = std::make_unique<t_mediator_command_response_get_mempool_transactions>();
			auto & response_as_get_mempool_txs = dynamic_cast<t_mediator_command_response_get_mempool_transactions&>(*response);
			response_as_get_mempool_txs.m_transactions = m_blockchain_module->get_mempool_transactions();
			break;
		}
		case t_mediator_cmd_type::e_get_block_by_id_proto:
		{
			const auto & request_get_block = dynamic_cast<const t_mediator_command_request_get_block_by_id_proto&>(request);
			auto block_proto = m_blockchain_module->get_block_at_hash_proto(request_get_block.m_block_hash);
			response = std::make_unique<t_mediator_command_response_get_block_by_id_proto>();
			auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_id_proto&>(*response);
			response_get_block.m_block_proto = std::move(block_proto);
			break;
		}
		case t_mediator_cmd_type::e_get_headers_proto:
		{
			const auto & request_get_headers = dynamic_cast<const t_mediator_command_request_get_headers_proto&>(request);
			auto headers = m_blockchain_module->get_headers_proto(request_get_headers.m_hash_begin, request_get_headers.m_hash_end);
			response = std::make_unique<t_mediator_command_response_get_headers_proto>();
			auto & response_get_headers = dynamic_cast<t_mediator_command_response_get_headers_proto&>(*response);
			response_get_headers.m_headers = std::move(headers);
			break;
		}
		case t_mediator_cmd_type::e_is_organizer_pk:
		{
			const auto & request_organizer_pk = dynamic_cast<const t_mediator_command_request_is_organizer_pk&>(request);
			const auto is_organizer_pk = m_blockchain_module->is_pk_organizer(request_organizer_pk.m_pk);
			response = std::make_unique<t_mediator_command_response_is_organizer_pk>();
			auto & response_is_pk_organizer = dynamic_cast<t_mediator_command_response_is_organizer_pk&>(*response);
			response_is_pk_organizer.m_is_organizer_pk = is_organizer_pk;
			break;
		}
		case t_mediator_cmd_type::e_get_mnemonic_sentence:
		{
			response = std::make_unique<t_mediator_command_response_get_mnemonic_sentence>();
			auto & response_get_mnemonic = dynamic_cast<t_mediator_command_response_get_mnemonic_sentence&>(*response);
			response_get_mnemonic.m_seed_words = m_wallet_module->get_words_of_seed();
			break;
		}
		case t_mediator_cmd_type::e_get_height:
		{
			response = std::make_unique<t_mediator_command_response_get_height>();
			auto & response_get_height = dynamic_cast<t_mediator_command_response_get_height&>(*response);
			if(m_blockchain_module->get_height()==std::numeric_limits<size_t>::max()) throw std::runtime_error("There is no blockchain");
			response_get_height.m_height = m_blockchain_module->get_height();
			break;
		}
		case t_mediator_cmd_type::e_is_authorized:
		{
			const auto &request_is_authorized = dynamic_cast<const t_mediator_command_request_is_authorized&>(request);
			const auto &pk = request_is_authorized.m_pk;
			response = std::make_unique<t_mediator_command_response_is_authorized>();
			auto &response_is_authorized = dynamic_cast<t_mediator_command_response_is_authorized&>(*response);
			const auto is_pk_adminsys = n_blockchainparams::is_pk_adminsys(pk);
			bool is_pk_organizer = false;
			bool is_pk_miner = false;
			if(is_pk_adminsys) {
				response_is_authorized.m_is_adminsys = is_pk_adminsys;
				response_is_authorized.m_is_miner = is_pk_miner;
				response_is_authorized.m_is_organizer = is_pk_organizer;
				response_is_authorized.m_txid_auth = m_blockchain_module->get_auth_txid(pk);
				break;
			} else {
				is_pk_organizer = m_blockchain_module->is_pk_organizer(pk);
				if(is_pk_organizer) {
					response_is_authorized.m_is_adminsys = is_pk_adminsys;
					response_is_authorized.m_is_miner = is_pk_miner;
					response_is_authorized.m_is_organizer = is_pk_organizer;
					response_is_authorized.m_txid_auth = m_blockchain_module->get_auth_txid(pk);
					break;
				} else {
					is_pk_miner = m_blockchain_module->is_pk_miner(pk);
					if(is_pk_miner) {
						response_is_authorized.m_is_adminsys = is_pk_adminsys;
						response_is_authorized.m_is_miner = is_pk_miner;
						response_is_authorized.m_is_organizer = is_pk_organizer;
						response_is_authorized.m_txid_auth = m_blockchain_module->get_auth_txid(pk);
						break;
					} else throw std::runtime_error("This pk is not authorized");
				}
			}
		}
		case t_mediator_cmd_type::e_get_pk_and_sign:
		{
			const auto pk = m_wallet_module->get_main_pk();
			const auto & sign_request = dynamic_cast<const t_mediator_command_request_get_pk_and_sign&>(request);
			const auto sign = m_wallet_module->sign_message_using_main_pk(sign_request.m_msg_to_sign);
			response = std::make_unique<t_mediator_command_response_get_pk_and_sign>();
			auto & response_get_pk_and_sign = dynamic_cast<t_mediator_command_response_get_pk_and_sign&>(*response);
			response_get_pk_and_sign.m_pk = pk;
			response_get_pk_and_sign.m_sign = sign;
			break;
		}
		case t_mediator_cmd_type::e_sign_message_by_main_identity:
		{
			const auto & request_sign = dynamic_cast<const t_mediator_command_request_sign_message_by_main_identity&>(request);
			const auto & msg_to_sign = request_sign.m_msg;
			const auto signature = m_wallet_module->sign_message_using_main_pk(msg_to_sign);
			response = std::make_unique<t_mediator_command_response_sign_message_by_main_identity>();
			auto & response_sign_message = dynamic_cast<t_mediator_command_response_sign_message_by_main_identity&>(*response);
			response_sign_message.m_sign = signature;
			break;
		}
		case t_mediator_cmd_type::e_sign_tx_by_main_identity:
		{
			const auto & request_sign_tx = dynamic_cast<const t_mediator_command_request_sign_tx_by_main_identity&>(request);
			const auto & tx_to_sign = request_sign_tx.m_transaction_to_sign;
			response = std::make_unique<t_mediator_command_response_sign_tx_by_main_identity>();
			auto & response_sign_tx = dynamic_cast<t_mediator_command_response_sign_tx_by_main_identity&>(*response);
			response_sign_tx.m_transaction_signature = m_wallet_module->sign_tx_by_main_identity(tx_to_sign);
			break;
		}
		case t_mediator_cmd_type::e_get_peers:
		{
			response = std::make_unique<t_mediator_command_response_get_peers>();
			auto & response_get_peers = dynamic_cast<t_mediator_command_response_get_peers&>(*response);
			response_get_peers.m_peers_tcp = m_p2p_module->get_peers_tcp();
			break;
		}
		case t_mediator_cmd_type::e_get_metadata_from_tx:
		{
			const auto & request_get_metadata_from_tx = dynamic_cast<const t_mediator_command_request_get_metadata_from_tx&>(request);
			auto tx = m_blockchain_module->get_transaction(request_get_metadata_from_tx.m_txid);
			response = std::make_unique<t_mediator_command_response_get_metadata_from_tx>();
			auto & response_get_metadata_from_tx = dynamic_cast<t_mediator_command_response_get_metadata_from_tx&>(*response);
			response_get_metadata_from_tx.m_metadata_from_tx = tx.m_allmetadata;
			break;
		}
		case t_mediator_cmd_type::e_get_last_block_time:
		{
			const auto block_time = m_blockchain_module->get_last_block_time();
			response = std::make_unique<t_mediator_command_response_get_last_block_time>();
			auto & response_get_last_block_time = dynamic_cast<t_mediator_command_response_get_last_block_time&>(*response);
			response_get_last_block_time.m_block_time = block_time;
			break;
		}
		case t_mediator_cmd_type::e_get_block_by_txid:
		{
			const auto & request_get_block = dynamic_cast<const t_mediator_command_request_get_block_by_txid&>(request);
			auto block = m_blockchain_module->get_block_by_txid(request_get_block.m_txid);
			response = std::make_unique<t_mediator_command_response_get_block_by_txid>();
			auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_txid&>(*response);
			response_get_block.m_block = std::move(block);
			break;
		}
		case t_mediator_cmd_type::e_get_merkle_branch:
		{
			const auto request_get_merkle_branch = dynamic_cast<const t_mediator_command_request_get_merkle_branch&>(request);
			const auto txid = request_get_merkle_branch.m_txid;
			const auto merkle_branch = m_blockchain_module->get_merkle_branch(txid);
			const auto block_id = m_blockchain_module->get_block_id_by_txid(txid);
			response = std::make_unique<t_mediator_command_response_get_merkle_branch>();
			auto & response_get_merkle_branch = dynamic_cast<t_mediator_command_response_get_merkle_branch&>(*response);
			response_get_merkle_branch.m_merkle_branch = merkle_branch;
			response_get_merkle_branch.m_block_id = block_id;
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_miners:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_miners>();
			auto & get_number_of_miners_response = dynamic_cast<t_mediator_command_response_get_number_of_miners&>(*response);
			get_number_of_miners_response.m_number_of_miners = m_blockchain_module->get_number_of_miners();
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_all_transactions:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_transactions>();
			auto & get_number_of_all_transactions = dynamic_cast<t_mediator_command_response_get_number_of_all_transactions&>(*response);
			get_number_of_all_transactions.m_number_of_all_transactions = m_blockchain_module->get_number_of_transactions();
			break;
		}
		case t_mediator_cmd_type::e_get_block_by_id_without_txs_and_signs:
		{
			const auto & request_get_block = dynamic_cast<const t_mediator_command_request_get_block_by_id_without_txs_and_signs&>(request);
			auto block = m_blockchain_module->get_block_at_hash(request_get_block.m_block_hash);
			response = std::make_unique<t_mediator_command_response_get_block_by_id_without_txs_and_signs>();
			auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_id_without_txs_and_signs&>(*response);
			response_get_block.m_block = std::move(block);
			break;
		}
		case t_mediator_cmd_type::e_get_block_by_height_without_txs_and_signs:
		{
			const auto & request_get_block = dynamic_cast<const t_mediator_command_request_get_block_by_height_without_txs_and_signs&>(request);
			auto block = m_blockchain_module->get_block_at_height(request_get_block.m_height);
			response = std::make_unique<t_mediator_command_response_get_block_by_height_without_txs_and_signs>();
			auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_height_without_txs_and_signs&>(*response);
			response_get_block.m_block = std::move(block);
			break;
		}
		case t_mediator_cmd_type::e_get_block_by_txid_without_txs_and_signs:
		{
			const auto & request_get_block = dynamic_cast<const t_mediator_command_request_get_block_by_txid_without_txs_and_signs&>(request);
			auto block = m_blockchain_module->get_block_by_txid(request_get_block.m_txid);
			response = std::make_unique<t_mediator_command_response_get_block_by_txid_without_txs_and_signs>();
			auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_txid_without_txs_and_signs&>(*response);
			response_get_block.m_block = std::move(block);
			break;
		}
		case t_mediator_cmd_type::e_get_sorted_blocks:
		{
			const auto & request_get_sorted_blocks = dynamic_cast<const t_mediator_command_request_get_sorted_blocks_without_txs_and_signs&>(request);
			auto blocks = m_blockchain_module->get_sorted_blocks(request_get_sorted_blocks.m_amount_of_blocks);
			response = std::make_unique<t_mediator_command_response_get_sorted_blocks_without_txs_and_signs>();
			auto & response_get_sorted_blocks = dynamic_cast<t_mediator_command_response_get_sorted_blocks_without_txs_and_signs&>(*response);
			response_get_sorted_blocks.m_blocks = std::move(blocks);
			break;
		}
		case t_mediator_cmd_type::e_get_sorted_blocks_per_page:
		{
			const auto & request_get_sorted_blocks_per_page = dynamic_cast<const t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs&>(request);
			auto blocks_and_current_height = m_blockchain_module->get_sorted_blocks_per_page(request_get_sorted_blocks_per_page.m_offset);
			response = std::make_unique<t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs>();
			auto & response_get_sorted_blocks_per_page = dynamic_cast<t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs&>(*response);
			response_get_sorted_blocks_per_page.m_blocks = std::move(blocks_and_current_height.first);
			response_get_sorted_blocks_per_page.m_current_height = blocks_and_current_height.second;
			break;
		}
		case t_mediator_cmd_type::e_get_latest_txs:
		{
			const auto & request_get_latest_txs = dynamic_cast<const t_mediator_command_request_get_latest_txs&>(request);
			auto txs = m_blockchain_module->get_latest_transactions(request_get_latest_txs.m_amount_txs);
			response = std::make_unique<t_mediator_command_response_get_latest_txs>();
			auto & get_latest_transactions = dynamic_cast<t_mediator_command_response_get_latest_txs&>(*response);
			get_latest_transactions.m_transactions = std::move(txs);
			break;
		}
		case t_mediator_cmd_type::e_get_txs_per_page:
		{
			const auto & request_get_txs_per_page = dynamic_cast<const t_mediator_command_request_get_txs_per_page&>(request);
			auto txs_and_total_number_txs = m_blockchain_module->get_txs_per_page(request_get_txs_per_page.m_offset);
			response = std::make_unique<t_mediator_command_response_get_txs_per_page>();
			auto & get_txs_per_page = dynamic_cast<t_mediator_command_response_get_txs_per_page&>(*response);
			get_txs_per_page.m_transactions = std::move(txs_and_total_number_txs.first);
			get_txs_per_page.m_total_number_txs = txs_and_total_number_txs.second;
			break;
		}
		case t_mediator_cmd_type::e_get_txs_from_block_per_page:
		{
			const auto & request_get_txs_per_page_from_block = dynamic_cast<const t_mediator_command_request_get_txs_from_block_per_page&>(request);
			auto txs_with_number_txs = m_blockchain_module->get_txs_from_block_per_page(request_get_txs_per_page_from_block.m_offset, request_get_txs_per_page_from_block.m_block_id);
			response = std::make_unique<t_mediator_command_response_get_txs_from_block_per_page>();
			auto & get_txs_per_page_from_block = dynamic_cast<t_mediator_command_response_get_txs_from_block_per_page&>(*response);
			get_txs_per_page_from_block.m_transactions = std::move(txs_with_number_txs.first);
			get_txs_per_page_from_block.m_number_txs = txs_with_number_txs.second;
			break;
		}
		case t_mediator_cmd_type::e_get_block_signatures_and_pk_miners_per_page:
		{
			const auto & request_get_block_signatures = dynamic_cast<const t_mediator_command_request_get_block_signatures_and_pks_miners_per_page&>(request);
			auto signs_pks_all_number_signs_from_block = m_blockchain_module->get_block_signatures_and_pk_miners_per_page(request_get_block_signatures.m_offset, request_get_block_signatures.m_block_id);
			response = std::make_unique<t_mediator_command_response_get_block_signatures_and_pks_miners_per_page>();
			auto & get_block_signs_pks_miners_all_number_signs_from_block = dynamic_cast<t_mediator_command_response_get_block_signatures_and_pks_miners_per_page&>(*response);
			get_block_signs_pks_miners_all_number_signs_from_block.m_number_signatures = signs_pks_all_number_signs_from_block.second;
			get_block_signs_pks_miners_all_number_signs_from_block.m_signatures_and_pks = std::move(signs_pks_all_number_signs_from_block.first);
			break;
		}
		case t_mediator_cmd_type::e_is_blockchain_synchronized:
		{
			response = std::make_unique<t_mediator_command_response_is_blockchain_synchronized>();
			auto & is_blockchain_synchronized = dynamic_cast<t_mediator_command_response_is_blockchain_synchronized&>(*response);
			is_blockchain_synchronized.m_is_blockchain_synchronized = m_blockchain_module->is_blockchain_synchronized();
			break;
		}
		case t_mediator_cmd_type::e_block_exists:
		{
			const auto request_block_exists = dynamic_cast<const t_mediator_command_request_block_exists&>(request);
			const auto & block_id = request_block_exists.m_block_id;
			response = std::make_unique<t_mediator_command_response_block_exists>();
			auto & block_exists = dynamic_cast<t_mediator_command_response_block_exists&>(*response);
			block_exists.m_block_exists = m_blockchain_module->block_exists(block_id);
			break;
		}

		default:
		break;
	}
	assert(response != nullptr);
	return response;
}

void c_main_module::run() {
	m_blockchain_module->run();
	m_wallet_module->run();
	m_rpc_module->run();
	m_p2p_module->run();
	std::unique_lock<std::mutex> lock(m_stop_cv_mutex);
	m_stop_cv.wait(lock, [this]{return m_stopped;});
}

void c_main_module::stop() {
	m_blockchain_module->stop();
	std::unique_lock<std::mutex> lock(m_stop_cv_mutex);
	m_stopped = true;
	lock.unlock();
	m_stop_cv.notify_one();
}
