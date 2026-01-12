#include "rpc_exec.hpp"
#include "mediator_commands.hpp"
#include "utils.hpp"
#include "rpc_module.hpp"
#include "wallet_module.hpp"
#include "params.hpp"
#include "types.hpp"
#include <iostream>
#include <sstream>

nlohmann::json c_rpc_exec::execute(const nlohmann::json & cmd) {
	std::lock_guard< std::mutex > lg( m_mutex );
	const std::string method = cmd.at("method").get<std::string>();
	const auto cmd_found = m_cmd_map.find( method );
		if (cmd_found == m_cmd_map.end()) {
			nlohmann::json result;
			result["id"] = cmd.at("id");
			result["error"]["message"] = "Method not found" ;
			return result;
		}
	auto result_full = (cmd_found->second)( cmd );
	nlohmann::json ret;
	ret["id"] = cmd.at("id");
	if (result_full.first == "done") {
		ret["result"]["status"] = "done";
		ret["result"]["data"] = result_full.second;
	}
	return ret;
}

void c_rpc_exec::add_method(const std::string &method, std::function<std::pair<std::string , nlohmann::json> (const nlohmann::json & )> &&exec) {
	const auto result =	m_cmd_map.emplace( method , exec );
	const bool added = result.second;
	if (!added) throw std::runtime_error("Method with this name already existed: \"" + method + "\"");
}

void c_rpc_exec::install_rpc_handlers() {
	add_method( "ping", [](const nlohmann::json & ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		result="pong";
		return std::make_pair( "done" , result );
	});

	add_method( "get_block_by_hash", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_block_by_id request_mediator;
		const std::string blockid_as_str = input.at("params").at("hash");
		t_hash_type blockid;
		if(blockid_as_str.size()!=blockid.size()*2) throw std::invalid_argument("Bad blockid size");
		const auto ret = sodium_hex2bin(blockid.data(), blockid.size(),
										blockid_as_str.data(), blockid_as_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_block_hash = blockid;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_block = dynamic_cast<const t_mediator_command_response_get_block_by_id &>(*response_mediator);
		const auto block = response_get_block.m_block;
		result = block;

		return std::make_pair( "done" , result );

	});

	add_method( "get_block_by_txid", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_block_by_txid request_mediator;
		const std::string txid_as_str = input.at("params").at("txid");
		t_hash_type txid;
		if(txid_as_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
		const auto ret = sodium_hex2bin(reinterpret_cast<unsigned char *>(txid.data()), txid.size(),
										txid_as_str.data(), txid_as_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_txid = txid;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_block = dynamic_cast<const t_mediator_command_response_get_block_by_txid &>(*response_mediator);
		const auto block = response_get_block.m_block;
		result = block;

		return std::make_pair( "done" , result );

	});

	add_method( "get_block_by_height", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_block_by_height request_mediator;
		const unsigned long height = input.at("params").at("height");
		request_mediator.m_height = height;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_block = dynamic_cast<const t_mediator_command_response_get_block_by_height &>(*response_mediator);
		const auto block = response_get_block.m_block;
		result = block;

		return std::make_pair( "done" , result );

	});

	add_method( "get_tx", [this](const nlohmann::json & input ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_tx request_mediator;
		const std::string txid_as_str = input.at("params").at("txid");
		t_hash_type txid;
		if(txid_as_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
		const auto ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_as_str.data(), txid_as_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_txid = txid;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_tx = dynamic_cast<const t_mediator_command_response_get_tx &>(*response_mediator);
		const auto tx = response_get_tx.m_transaction;
		result = tx;

		return std::make_pair( "done" , result );

	});

	add_method( "get_pk_and_sign", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_pk_and_sign request_mediator;
		request_mediator.m_msg_to_sign = input.at("params").at("message");
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto signature = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_pk_and_sign = dynamic_cast<const t_mediator_command_response_get_pk_and_sign &>(*response_mediator);
		const auto pk = response_get_pk_and_sign.m_pk;
		const auto sign = response_get_pk_and_sign.m_sign;
		std::string pk_str;
		pk_str.resize(pk.size()*2+1);
		sodium_bin2hex(pk_str.data(), pk_str.size(), pk.data(), pk.size());
		std::string sign_str;
		sign_str.resize(sign.size()*2+1);
		sodium_bin2hex(sign_str.data(), sign_str.size(), sign.data(), sign.size());
		result["pk"] = pk_str.c_str();
		result["sign"] = sign_str.c_str();
		result["message"] = input.at("params").at("message");

		return std::make_pair( "done" , result );

	});

	add_method( "get_pk", [this](const nlohmann::json & ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_pk request_mediator;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_pk = dynamic_cast<const t_mediator_command_response_get_pk &>(*response_mediator);
		const auto pk = response_get_pk.m_pk;
		std::string pk_str;
		pk_str.resize(pk.size()*2+1);
		sodium_bin2hex(pk_str.data(), pk_str.size(), pk.data(), pk.size());
		result["pk"] = pk_str.c_str();

		return std::make_pair( "done" , result );
	});

	add_method("verify_pk", [](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		const std::string sign_str = input.at("params").at("sign");
		t_signature_type sign;
		if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
		int ret = 0;
		ret = sodium_hex2bin(sign.data(), sign.size(),
							 sign_str.data(), sign_str.size(),
							 nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string message = input["params"]["message"];
		const std::string pk_str = input["params"]["pk"];
		t_public_key_type pk;
		if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(pk.data(), pk.size(),
							 pk_str.data(), pk_str.size(),
							 nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		ret = crypto_sign_verify_detached(sign.data(),
													 reinterpret_cast<const unsigned char *>(message.data()),
													 message.size(),
													 pk.data());
		if (ret == 0) result = true;
		else result = false;
		return std::make_pair( "done" , result );
	});

	add_method("authorize_organizer_by_admin", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		const std::string pk_str = input.at("params").at("pk");
		t_public_key_type pk;
		if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
		const auto ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_mediator_command_request_authorize_organizer_by_admin request_mediator;
		request_mediator.m_organizer_pk = pk;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_authorize_organizer_by_admin =
				dynamic_cast<const t_mediator_command_response_authorize_organizer_by_admin &>(*response_mediator);
		const auto txid = response_authorize_organizer_by_admin.m_txid_auth_organizer;

		std::string txid_hex_str;
		txid_hex_str.resize(2*txid.size()+1);
		sodium_bin2hex(txid_hex_str.data(), txid_hex_str.size(), txid.data(), txid.size());
		txid_hex_str.pop_back();
		result["authorize_organizer_by_admin"] = txid_hex_str;

		return std::make_pair( "done" , result );
	});

	add_method("authorize_miner_by_admin", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_authorize_miner_by_admin request_mediator;
		const std::string pk_str = input.at("params").at("pk");
		t_public_key_type pk;
		if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
		const auto ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_miner_pk = pk;
		const auto response_mediator  = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_authorize_miner_by_admin =
				dynamic_cast<const t_mediator_command_response_authorize_miner_by_admin &>(*response_mediator);
		const auto txid = response_authorize_miner_by_admin.m_txid_auth_miner;

		std::string txid_hex_str;
		txid_hex_str.resize(2*txid.size()+1);
		sodium_bin2hex(txid_hex_str.data(), txid_hex_str.size(), txid.data(), txid.size());
		txid_hex_str.pop_back();
		result["authorize_miner_by_admin"] = txid_hex_str;

		return std::make_pair( "done" , result );
	});

	add_method("get_seed_words", [this](const nlohmann::json & ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_mnemonic_sentence request_mediator;
		const auto response_mediator  = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_mnemonic_sentence 
				= dynamic_cast<const t_mediator_command_response_get_mnemonic_sentence&>(*response_mediator);
		result = response_mnemonic_sentence.m_seed_words;
		return std::make_pair( "done" , result );
	});
	
	add_method("restore_key_from_seed", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_set_key_from_mnemonic mediator_request;
		mediator_request.m_seed_words = input.at("params");
		m_rpc_module->notify_mediator(mediator_request);
		return std::make_pair( "done" , result );
	});

	add_method( "get_height", [this](const nlohmann::json & ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_height request_mediator;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_height = dynamic_cast<const t_mediator_command_response_get_height &>(*response_mediator);
		const auto height = response_height.m_height;
		result["height"] = height;
		return std::make_pair( "done" , result );

	});

	add_method("add_tx_to_mempool", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_add_transaction_to_mempool request_mediator;
		request_mediator.m_tx = input.at("params");
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		return std::make_pair( "done" , result);
	});

	add_method("is_pk_authorized", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_is_authorized request_mediator;
		const std::string pk_as_str = input.at("params").at("pk");
		t_public_key_type pk;
		if(pk_as_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
		const auto ret_pk = sodium_hex2bin(pk.data(), pk.size(),
										   pk_as_str.data(), pk_as_str.size(),
										   nullptr, nullptr, nullptr);
		if (ret_pk!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_pk = pk;
		const auto response_mediator  = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_auth_data = dynamic_cast<const t_mediator_command_response_is_authorized&>(*response_mediator);
		const auto txid = response_auth_data.m_txid_auth;
		std::string txid_hex_str;
		txid_hex_str.resize(2*txid.size()+1);
		sodium_bin2hex(txid_hex_str.data(), txid_hex_str.size(), txid.data(), txid.size());
		txid_hex_str.pop_back();
		if(response_auth_data.m_is_adminsys==false && response_auth_data.m_is_miner==false && response_auth_data.m_is_organizer==false) {
			result = "This public key is not authorized";
			return std::make_pair( "done" , result );
		} else if(response_auth_data.m_is_adminsys==true && response_auth_data.m_is_miner==false && response_auth_data.m_is_organizer==false) {
			result["adminsys_pk"] = true;
			result["organizer_pk"] = false;
			result["miner_pk"] = false;
			result["txid_authorization"] = txid_hex_str;
		} else if(response_auth_data.m_is_adminsys==false && response_auth_data.m_is_miner==true && response_auth_data.m_is_organizer==false) {
			result["adminsys_pk"] = false;
			result["organizer_pk"] = false;
			result["miner_pk"] = true;
			result["txid_authorization"] = txid_hex_str;
		} else if(response_auth_data.m_is_adminsys==false && response_auth_data.m_is_miner==false && response_auth_data.m_is_organizer==true) {
			result["adminsys_pk"] = false;
			result["organizer_pk"] = true;
			result["miner_pk"] = false;
			result["txid_authorization"] = txid_hex_str;
		} else throw std::runtime_error("this public key is authorized more than once");

		return std::make_pair( "done" , result );
	});

	add_method("get_peers", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_peers request_mediator;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_peers = dynamic_cast<const t_mediator_command_response_get_peers&>(*response_mediator);
		nlohmann::json peers_tcp_str;
		for(const auto &peer:response_peers.m_peers_tcp) {
			peers_tcp_str.push_back(peer->to_string());
		}
		nlohmann::json peers_tor_str;
		for(const auto &peer:response_peers.m_peers_tor) {
			peers_tor_str.push_back(peer->to_string());
		}
		result["peers_tcp"] = peers_tcp_str;
		result["peers_tor"] = peers_tor_str;

		return std::make_pair( "done" , result);
	});

	add_method("get_transactions_from_mempool", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_mempool_transactions request_mediator;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_transactions_from_mempool = dynamic_cast<const t_mediator_command_response_get_mempool_transactions&>(*response_mediator);
		nlohmann::json txs;
		for(const auto &tx:response_transactions_from_mempool.m_transactions) {
			txs.push_back(tx);
		}
		result["transactions"] = txs;

		return std::make_pair( "done" , result);
	});

	add_method("add_voting_protocol", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		const std::string voting_data_as_str = input.at("params").at("voting_protocol");
		t_mediator_command_request_add_voting_protocol request;
		request.m_voting_protocol = container_to_vector_of_uchars(voting_data_as_str); //need not be added binary.
		const auto response = m_rpc_module->notify_mediator(request);
		const auto & response_add_another_voting_protocol = dynamic_cast<const t_mediator_command_response_add_voting_protocol&>(*response);
		const auto & txid = response_add_another_voting_protocol.m_txid;
		std::string txid_str;
		txid_str.resize(txid.size()*2+1);
		sodium_bin2hex(txid_str.data(),
		                txid_str.size(),
		                txid.data(),
		                txid.size());
		nlohmann::json result;
		result["txid"] = txid_str.c_str();
		return std::make_pair( "done" , result);
	});

	add_method( "get_metadata_from_tx", [this](const nlohmann::json & input ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_metadata_from_tx request_mediator;
		const std::string txid_as_str = input.at("params").at("txid");
		t_hash_type txid;
		if(txid_as_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
		const auto ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_as_str.data(), txid_as_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_txid = txid;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_metadata_from_tx = dynamic_cast<const t_mediator_command_response_get_metadata_from_tx &>(*response_mediator);
		const auto metadata = response_get_metadata_from_tx.m_metadata_from_tx;
		std::string metadata_str;
		metadata_str.resize(metadata.size()*2+1);
		sodium_bin2hex(metadata_str.data(),
						metadata_str.size(),
						metadata.data(),
						metadata.size());
		result["metadata"] = metadata_str.c_str();

		return std::make_pair( "done" , result );

	});

	add_method( "get_last_block_time", [this](const nlohmann::json & ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_last_block_time request_mediator;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_last_block_time = dynamic_cast<const t_mediator_command_response_get_last_block_time &>(*response_mediator);
		const auto block_time = response_get_last_block_time.m_block_time;

		result["last_block_time"] = block_time;

		return std::make_pair( "done" , result );
	});

	add_method("get_number_of_miners", [this](const nlohmann::json & ) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_miners request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_of_miners = dynamic_cast<const t_mediator_command_response_get_number_of_miners&>(*response);

		result["number_of_miners"] = response_get_number_of_miners.m_number_of_miners;
		return std::make_pair( "done" , result );
	});

	add_method("get_number_of_all_transactions", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_all_transactions request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_all_transactions = dynamic_cast<const t_mediator_command_response_get_number_of_all_transactions&>(*response);
		result = response_get_number_all_transactions.m_number_of_all_transactions;
		return std::make_pair( "done" , result );
	});

	add_method( "get_block_by_id_without_txs_and_signs", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_block_by_id_without_txs_and_signs request_mediator;
		const std::string block_id_as_str = input.at("params").at("block_id");
		t_hash_type block_id;
		if(block_id_as_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad block_id size");
		const auto ret = sodium_hex2bin(reinterpret_cast<unsigned char *>(block_id.data()), block_id.size(),
		                                block_id_as_str.data(), block_id_as_str.size(),
		                                nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_block_hash = block_id;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_block = dynamic_cast<const t_mediator_command_response_get_block_by_id_without_txs_and_signs &>(*response_mediator);
		const auto block = response_get_block.m_block;
		result["version"] = block.m_header.m_version;
		std::string parent_hash_str;
		parent_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(parent_hash_str.data(),
		                parent_hash_str.size(),
		                block.m_header.m_parent_hash.data(),
		                block.m_header.m_parent_hash.size());
		result["parent_hash"] = parent_hash_str.c_str();
		std::string actual_hash_str;
		actual_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(actual_hash_str.data(),
		                actual_hash_str.size(),
		                block.m_header.m_actual_hash.data(),
		                block.m_header.m_actual_hash.size());
		result["actual_hash"] = actual_hash_str.c_str();
		std::string all_tx_hash_str;
		all_tx_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(all_tx_hash_str.data(),
		                all_tx_hash_str.size(),
		                block.m_header.m_all_tx_hash.data(),
		                block.m_header.m_all_tx_hash.size());
		result["all_tx_hash"] = all_tx_hash_str.c_str();
		result["block_time"] = block.m_header.m_block_time;
		result["number_of_transactions"] = block.m_transaction.size();

		return std::make_pair( "done" , result );
	});

	add_method( "get_block_by_height_without_txs_and_signs", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_block_by_height_without_txs_and_signs request_mediator;
		const unsigned long height = input.at("params").at("height");
		request_mediator.m_height = height;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_block = dynamic_cast<const t_mediator_command_response_get_block_by_height_without_txs_and_signs &>(*response_mediator);
		const auto block = response_get_block.m_block;
		result["version"] = block.m_header.m_version;
		std::string parent_hash_str;
		parent_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(parent_hash_str.data(),
		                parent_hash_str.size(),
		                block.m_header.m_parent_hash.data(),
		                block.m_header.m_parent_hash.size());
		result["parent_hash"] = parent_hash_str.c_str();
		std::string actual_hash_str;
		actual_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(actual_hash_str.data(),
		                actual_hash_str.size(),
		                block.m_header.m_actual_hash.data(),
		                block.m_header.m_actual_hash.size());
		result["actual_hash"] = actual_hash_str.c_str();
		std::string all_tx_hash_str;
		all_tx_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(all_tx_hash_str.data(),
		                all_tx_hash_str.size(),
		                block.m_header.m_all_tx_hash.data(),
		                block.m_header.m_all_tx_hash.size());
		result["all_tx_hash"] = all_tx_hash_str.c_str();
		result["block_time"] = block.m_header.m_block_time;
		result["number_of_transactions"] = block.m_transaction.size();

		return std::make_pair( "done" , result );
	});

	add_method( "get_block_by_txid_without_txs_and_signs", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;

		t_mediator_command_request_get_block_by_txid_without_txs_and_signs request_mediator;
		const std::string txid_as_str = input.at("params").at("txid");
		t_hash_type txid;
		if(txid_as_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
		const auto ret = sodium_hex2bin(reinterpret_cast<unsigned char *>(txid.data()), txid.size(),
		                                txid_as_str.data(), txid_as_str.size(),
		                                nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_txid = txid;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_block = dynamic_cast<const t_mediator_command_response_get_block_by_txid_without_txs_and_signs &>(*response_mediator);
		const auto block = response_get_block.m_block;
		result["version"] = block.m_header.m_version;
		std::string parent_hash_str;
		parent_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(parent_hash_str.data(),
		                parent_hash_str.size(),
		                block.m_header.m_parent_hash.data(),
		                block.m_header.m_parent_hash.size());
		result["parent_hash"] = parent_hash_str.c_str();
		std::string actual_hash_str;
		actual_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(actual_hash_str.data(),
		                actual_hash_str.size(),
		                block.m_header.m_actual_hash.data(),
		                block.m_header.m_actual_hash.size());
		result["actual_hash"] = actual_hash_str.c_str();
		std::string all_tx_hash_str;
		all_tx_hash_str.resize(hash_size*2+1);
		sodium_bin2hex(all_tx_hash_str.data(),
		                all_tx_hash_str.size(),
		                block.m_header.m_all_tx_hash.data(),
		                block.m_header.m_all_tx_hash.size());
		result["all_tx_hash"] = all_tx_hash_str.c_str();
		result["block_time"] = block.m_header.m_block_time;
		result["number_of_transactions"] = block.m_transaction.size();

		return std::make_pair( "done" , result );

	});
	
	add_method("get_sorted_blocks", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_sorted_blocks_without_txs_and_signs request_mediator;
		const unsigned long amount_of_blocks = input.at("params").at("amount");
		request_mediator.m_amount_of_blocks = amount_of_blocks;
		const auto response = m_rpc_module->notify_mediator(request_mediator);
		const auto response_get_sorted_blocks = dynamic_cast<const t_mediator_command_response_get_sorted_blocks_without_txs_and_signs&>(*response);
		for(const auto &block: response_get_sorted_blocks.m_blocks) {
			nlohmann::json block_data;
			std::string block_id_str;
			block_id_str.resize(hash_size*2+1);
			sodium_bin2hex(block_id_str.data(),
			                block_id_str.size(),
			                block.m_header.m_actual_hash.data(),
			                block.m_header.m_actual_hash.size());
			block_data["block_id"] = block_id_str.c_str();
			block_data["block_time"] = block.m_header.m_block_time;
			block_data["number_of_transactions"] = block.m_number_of_transactions;
			result.push_back(block_data);
		}
		return std::make_pair( "done" , result );
	});
	
	add_method("get_sorted_blocks_per_page", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs request_mediator;
		const unsigned long offset = input.at("params").at("offset");
		request_mediator.m_offset = offset;
		const auto response = m_rpc_module->notify_mediator(request_mediator);
		const auto response_get_sorted_blocks_per_page = dynamic_cast<const t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs&>(*response);
		result["total_number_blocks"] = response_get_sorted_blocks_per_page.m_current_height;
		for(const auto &block: response_get_sorted_blocks_per_page.m_blocks) {
			nlohmann::json block_data;
			std::string block_id_str;
			block_id_str.resize(hash_size*2+1);
			sodium_bin2hex(block_id_str.data(),
			                block_id_str.size(),
			                block.m_header.m_actual_hash.data(),
			                block.m_header.m_actual_hash.size());
			block_data["block_id"] = block_id_str.c_str();
			block_data["block_time"] = block.m_header.m_block_time;
			block_data["number_of_transactions"] = block.m_number_of_transactions;
			result["blocks"].push_back(block_data);
		}
		return std::make_pair( "done" , result );
	});
	
	add_method("get_latest_transactions", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_latest_txs request;
		const unsigned long amount = input.at("params").at("amount");
		request.m_amount_txs = amount;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_latest_transactions = dynamic_cast<const t_mediator_command_response_get_latest_txs&>(*response);
		for(const auto &tx:response_get_latest_transactions.m_transactions) {
			result.push_back(tx);
		}
		return std::make_pair( "done" , result );
	});
	
	add_method("get_transactions_per_page", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_txs_per_page request;
		const unsigned long offset = input.at("params").at("offset");
		request.m_offset = offset;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_transactions_per_page = dynamic_cast<const t_mediator_command_response_get_txs_per_page&>(*response);
		result["total_number_txs"] = response_get_transactions_per_page.m_total_number_txs;
		for(const auto &tx:response_get_transactions_per_page.m_transactions) {
			result["txs"].push_back(tx);
		}
		return std::make_pair( "done" , result );
	});

	add_method("get_transactions_from_block_per_page", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_txs_from_block_per_page request;
		const unsigned long offset = input.at("params").at("offset");
		request.m_offset = offset;
		const std::string blockid_as_str = input.at("params").at("block_id");
		t_hash_type blockid;
		if(blockid_as_str.size()!=blockid.size()*2) throw std::invalid_argument("Bad blockid size");
		const auto ret = sodium_hex2bin(blockid.data(), blockid.size(),
		                                blockid_as_str.data(), blockid_as_str.size(),
		                                nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request.m_block_id = blockid;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_transactions_from_block_per_page = dynamic_cast<const t_mediator_command_response_get_txs_from_block_per_page&>(*response);
		result["number_transactions_from_block"] = response_get_transactions_from_block_per_page.m_number_txs;
		for(const auto &tx:response_get_transactions_from_block_per_page.m_transactions) {
			result["transactions_from_block"].push_back(tx);
		}
		return std::make_pair( "done" , result );
	});

	add_method("get_block_signatures_and_miners_public_keys_per_page", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_block_signatures_and_pks_miners_per_page request;
		const unsigned long offset = input.at("params").at("offset");
		request.m_offset = offset;
		const std::string blockid_as_str = input.at("params").at("block_id");
		t_hash_type blockid;
		if(blockid_as_str.size()!=blockid.size()*2) throw std::invalid_argument("Bad blockid size");
		const auto ret = sodium_hex2bin(blockid.data(), blockid.size(),
		                                blockid_as_str.data(), blockid_as_str.size(),
		                                nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request.m_block_id = blockid;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_block_signatures_and_pks_miners_per_page = dynamic_cast<const t_mediator_command_response_get_block_signatures_and_pks_miners_per_page&>(*response);
		result["number_signatures_from_block"] = response_get_block_signatures_and_pks_miners_per_page.m_number_signatures;
		for(const auto &sign_and_pk:response_get_block_signatures_and_pks_miners_per_page.m_signatures_and_pks) {
			nlohmann::json sign_and_pk_data;
			std::string signature_str;
			signature_str.resize(signature_size*2+1);
			sodium_bin2hex(signature_str.data(),
			                signature_str.size(),
			                sign_and_pk.first.data(),
			                sign_and_pk.first.size());
			std::string pk_str;
			pk_str.resize(public_key_size*2+1);
			sodium_bin2hex(pk_str.data(),
			                pk_str.size(),
			                sign_and_pk.second.data(),
			                sign_and_pk.second.size());
			sign_and_pk_data["signature"] = signature_str.c_str();
			sign_and_pk_data["public_key"] = pk_str.c_str();
			result["signatures_and_public_keys"].push_back(sign_and_pk_data);
		}
		return std::make_pair( "done" , result );
	});
}
void c_rpc_exec::set_rpc_module(c_rpc_module &rpc_module) {
    m_rpc_module = &rpc_module;
}
