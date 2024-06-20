#include "rpc_exec.hpp"
#include "mediator_commands.hpp"
#include "utils.hpp"
#include "rpc_module.hpp"
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

	add_method("get_authorize_level_of_voter", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_voter_auth_data request_mediator;
		const std::string pk_str = input.at("params").at("pk");
		t_public_key_type pk;
		if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
		const auto ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_pk_voter = pk;
		const auto response_mediator  = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_auth_level =
				dynamic_cast<const t_mediator_command_response_get_voter_auth_data &>(*response_mediator);
		const auto auth_level_bin = response_auth_level.m_auth_level;
		std::map<std::string, uint32_t> color_str_auth_level;
		for (const auto& [co_color, auth_level]:auth_level_bin) { 
			std::string co_color_hex_str;
			co_color_hex_str.resize(2*co_color.size()+1);
			sodium_bin2hex(co_color_hex_str.data(), co_color_hex_str.size(), co_color.data(), co_color.size());
			co_color_hex_str.pop_back();
			color_str_auth_level.emplace(co_color_hex_str, auth_level);
		}
		result["authorization_level"] = color_str_auth_level;

		return std::make_pair( "done" , result );
	});

	add_method("get_personal_data", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_personal_data request_mediator;
		const std::string pk_voter_str = input.at("params").at("pk_voter");
		t_public_key_type pk_voter;
		if(pk_voter_str.size()!=pk_voter.size()*2) throw std::invalid_argument("Bad size of pk");
		const auto ret_pk = sodium_hex2bin(pk_voter.data(), pk_voter.size(),
										   pk_voter_str.data(), pk_voter_str.size(),
										   nullptr, nullptr, nullptr);
		if (ret_pk!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_pk_voter = pk_voter;
		const auto response_mediator  = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_hash_personal_data =
				dynamic_cast<const t_mediator_command_response_get_personal_data &>(*response_mediator);
		const auto hash_personal_data = response_hash_personal_data.m_hash_personal_data;
		std::string hash_hex_str;
		hash_hex_str.resize(2*hash_personal_data.size()+1);
		sodium_bin2hex(hash_hex_str.data(), hash_hex_str.size(),
					   hash_personal_data.data(), hash_personal_data.size());
		hash_hex_str.pop_back();
		result["hash_personal_data"] = hash_hex_str;

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

	add_method( "voting_results", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_voting_results request_mediator;
		const std::string txid_as_str = input.at("params").at("txid_create_voting");
		t_hash_type txid;
		if(txid_as_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
		const auto ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_as_str.data(), txid_as_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_txid_create_voting = txid;

		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_get_voting_results = dynamic_cast<const t_mediator_command_response_get_voting_results &>(*response_mediator);
		const auto voting_results = response_get_voting_results.m_voting_results;

		result["voting_name"] = response_get_voting_results.m_voting_name;
		result["voting_question"] = response_get_voting_results.m_question;
		for(const auto &option:voting_results) {
			const auto &name_of_option = option.first;
			result["options"][name_of_option] = option.second;
		}
		result["number_of_authorized_voters"] = response_get_voting_results.m_number_of_authorized_voters;

		return std::make_pair( "done" , result );
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
		if(response_auth_data.m_is_adminsys) {
			result = "This public key is the adminsys public key";
			return std::make_pair( "done" , result );
		}
		if(response_auth_data.m_auth_data.empty()) {
			result = "This public key is not authorized";
			return std::make_pair( "done" , result );
		}
		for(const auto & auth_data:response_auth_data.m_auth_data) {
			nlohmann::json authorization_data;
			const auto txid = auth_data.m_txid;
			std::string txid_str;
			txid_str.resize(2*txid.size()+1);
			sodium_bin2hex(txid_str.data(), txid_str.size(),
			               txid.data(), txid.size());
			txid_str.pop_back();
			authorization_data["txid"] = txid_str;
			authorization_data["type_of_authorized"] = auth_data.m_type_of_transaction;
			const auto voting_group = auth_data.m_voting_group;
			std::string voting_group_str;
			voting_group_str.resize(2*voting_group.size()+1);
			sodium_bin2hex(voting_group_str.data(), voting_group_str.size(),
			               voting_group.data(), voting_group.size());
			voting_group_str.pop_back();
			authorization_data["voting_group"] = voting_group_str;
			result["authorizations_data"].push_back(authorization_data);
		}

		return std::make_pair( "done" , result );
	});

	add_method("get_active_votings_for_voter", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_all_active_votings_for_voter request_mediator;
		const std::string pk_as_str = input.at("params").at("voter_pk");
		t_public_key_type pk;
		if(pk_as_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
		const auto ret_pk = sodium_hex2bin(pk.data(), pk.size(),
		                                   pk_as_str.data(), pk_as_str.size(),
		                                   nullptr, nullptr, nullptr);
		if (ret_pk!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_voter_pk = pk;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_active_votings_voter = dynamic_cast<const t_mediator_command_response_get_all_active_votings_for_voter&>(*response_mediator);
		const auto all_active_votings_for_voter = response_active_votings_voter.m_active_votings;
		for(const auto &voting:all_active_votings_for_voter) {
			nlohmann::json voting_details;
			const auto &voting_id = voting.first;
			std::string voting_id_str;
			voting_id_str.resize(2*voting_id.size()+1);
			sodium_bin2hex(voting_id_str.data(), voting_id_str.size(),
						   voting_id.data(), voting_id.size());
			voting_id_str.pop_back();
			voting_details["voting_id"] = voting_id_str;
			voting_details["name"] = voting.second.m_name;
			voting_details["question"] = voting.second.m_question;
			nlohmann::json options;
			for(const auto &option:voting.second.m_options) {
				options.push_back(option);
			}
			voting_details["options"] = options;
			voting_details["number_of_choice"] = voting.second.m_number_of_choice;
			voting_details["authorization_level"] = voting.second.m_authorization_level;
			voting_details["voting_start_time"] = voting.second.m_start_timepoint;
			voting_details["voting_end_time"] = voting.second.m_start_timepoint + 
												voting.second.m_number_of_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;
			result.push_back(voting_details);
		}

		return std::make_pair( "done" , result);
	});

	add_method("get_voting_details", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_voting_details request_mediator;
		const std::string voting_id_as_str = input.at("params").at("voting_id");
		t_hash_type voting_id;
		if(voting_id_as_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad txid size");
		const auto ret_voting_id = sodium_hex2bin(voting_id.data(), voting_id.size(),
		                                   voting_id_as_str.data(), voting_id_as_str.size(),
		                                   nullptr, nullptr, nullptr);
		if (ret_voting_id!=0) throw std::runtime_error("hex2bin error");
		request_mediator.m_voting_id = voting_id;
		const auto response_mediator = m_rpc_module->notify_mediator(request_mediator);
		const auto & response_voting_details = dynamic_cast<const t_mediator_command_response_get_voting_details&>(*response_mediator);
		const auto voting_details = response_voting_details.m_voting_details;
		result["name"] = voting_details.m_name;
		result["question"] = voting_details.m_question;
		nlohmann::json options;
		for(const auto &option:voting_details.m_options) {
			options.push_back(option);
		}
		result["options"] = options;
		result["number_of_choice"] = voting_details.m_number_of_choice;
		result["authorization_level"] = voting_details.m_authorization_level;
		result["voting_start_time"] = voting_details.m_start_timepoint;
		result["voting_end_time"] = voting_details.m_start_timepoint + 
									voting_details.m_number_of_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;

		return std::make_pair( "done" , result);
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

	add_method( "get_source_txid", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		const std::string pk_as_str = input.at("params").at("pk");
		t_public_key_type pk;
		if(pk_as_str.size() != pk.size()*2) throw std::invalid_argument("Bad public key size");
		auto ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_as_str.data(), pk_as_str.size(),
										nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string voting_id_as_str = input.at("params").at("voting_id");
		t_hash_type voting_id;
		if(voting_id_as_str.size() != voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
									voting_id_as_str.data(), voting_id_as_str.size(),
									nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");	
		bool is_pk_voter = false;
		t_mediator_command_request_is_authorized request_is_authorized;
		request_is_authorized.m_pk = pk;
		const auto response = m_rpc_module->notify_mediator(request_is_authorized);
		const auto & response_is_authorized = dynamic_cast<const t_mediator_command_response_is_authorized&>(*response);
		if(response_is_authorized.m_is_adminsys) throw std::invalid_argument("This public key is adminsys pk");
		if(response_is_authorized.m_auth_data.empty()) throw std::invalid_argument("This public key is not authorized");
		for(const auto &auth_data:response_is_authorized.m_auth_data){
			if(auth_data.m_type_of_transaction == t_transactiontype::authorize_voter) {
				is_pk_voter = true;
				break;
			}
		}
		if (is_pk_voter) {
			t_mediator_command_request_get_voter_auth_txid_for_voting request;
			request.m_voter_pk = pk;
			request.m_voting_id = voting_id;
			const auto response = m_rpc_module->notify_mediator(request);
			const auto & response_get_voter_txid = dynamic_cast<const t_mediator_command_response_get_voter_auth_txid_for_voting&>(*response);
			std::string txid_str;
			txid_str.resize(hash_size*2+1);
			sodium_bin2hex(txid_str.data(),
			                txid_str.size(),
			                response_get_voter_txid.m_txid.data(),
			                response_get_voter_txid.m_txid.size());
			txid_str.pop_back();
			result = txid_str;
		} else {
			t_mediator_command_request_get_source_txid_for_pkh request;
			request.m_pkh = generate_hash(pk);
			const auto response = m_rpc_module->notify_mediator(request);
			const auto & response_get_txid = dynamic_cast<const t_mediator_command_response_get_source_txid_for_pkh&>(*response);
			std::string txid_str;
			txid_str.resize(hash_size*2+1);
			sodium_bin2hex(txid_str.data(),
			                txid_str.size(),
			                response_get_txid.m_txid.data(),
			                response_get_txid.m_txid.size());
			txid_str.pop_back();
			result = txid_str;
		}
		return std::make_pair( "done" , result );
	});

	add_method("get_all_vote_transactions", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		const std::string voting_id_as_str = input.at("params").at("voting_id");
		t_hash_type voting_id;
		if(voting_id_as_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad txid size");
		const auto ret_voting_id = sodium_hex2bin(reinterpret_cast<unsigned char *>(voting_id.data()), voting_id.size(),
		                                   voting_id_as_str.data(), voting_id_as_str.size(),
		                                   nullptr, nullptr, nullptr);
		if (ret_voting_id!=0) throw std::runtime_error("hex2bin error");
		t_mediator_command_request_get_all_vote_transactions request;
		request.m_voting_id = voting_id;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_txs = dynamic_cast<const t_mediator_command_response_get_all_vote_transactions&>(*response);
		result = response_get_txs.m_vote_transactions;
		return std::make_pair( "done" , result );
	});

	add_method("get_voter_groups", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		const std::string voter_pk_str = input.at("params").at("voter_pk");
		t_public_key_type voter_pk;
		if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad voter pk size");
		const auto ret_voter_pk = sodium_hex2bin(reinterpret_cast<unsigned char *>(voter_pk.data()), voter_pk.size(),
		                                   voter_pk_str.data(), voter_pk_str.size(),
		                                   nullptr, nullptr, nullptr);
		if (ret_voter_pk!=0) throw std::runtime_error("hex2bin error");
		t_mediator_command_request_get_voter_groups request;
		request.m_voter_pk = voter_pk;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_voter_groups = dynamic_cast<const t_mediator_command_response_get_voter_groups&>(*response);
		for(const auto &voter_group:response_get_voter_groups.m_voter_groups) {
			std::string voter_group_str;
			voter_group_str.resize(public_key_size*2+1);
			sodium_bin2hex(voter_group_str.data(),
			               voter_group_str.size(),
			               voter_group.data(),
			               voter_group.size());
			voter_group_str.pop_back();
			result["voter_groups"].push_back(voter_group_str);
		}

		return std::make_pair( "done" , result );
	});

	add_method("get_number_of_all_voters", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_all_voters request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_voters = dynamic_cast<const t_mediator_command_response_get_number_of_all_voters&>(*response);

		result["number_of_all_voters"] = response_get_number_voters.m_number_of_all_voters;
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

	add_method("get_number_of_all_active_votings", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_all_active_votings request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_of_all_active_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_active_votings&>(*response);
		result = response_get_number_of_all_active_votings.m_number_of_all_active_votings;
		return std::make_pair( "done" , result );
	});
	
	add_method("get_number_of_all_votings", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_all_votings request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_all_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_votings&>(*response);
		result = response_get_number_all_votings.m_number_of_all_votings;
		return std::make_pair( "done" , result );
	});
	
	add_method("get_number_of_all_inactive_votings", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_all_inactive_votings request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_all_inactive_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_inactive_votings&>(*response);
		result = response_get_number_all_inactive_votings.m_number_of_all_inactive_votings;
		return std::make_pair( "done" , result );
	});

	add_method("get_number_of_all_finished_votings", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_all_finished_votings request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_all_finished_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_finished_votings&>(*response);
		result = response_get_number_all_finished_votings.m_number_of_all_finished_votings;
		return std::make_pair( "done" , result );
	});

	add_method("get_number_of_all_added_votes", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_number_of_all_added_votes request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_number_all_added_votes = dynamic_cast<const t_mediator_command_response_get_number_of_all_added_votes&>(*response);
		result = response_get_number_all_added_votes.m_number_of_all_added_votes;
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
	
	add_method("get_last_5_blocks", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_last_5_blocks request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_last_5_blocks = dynamic_cast<const t_mediator_command_response_get_last_5_blocks&>(*response);
		for(const auto &block: response_get_last_5_blocks.m_last_5_blocks) {
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

	add_method("get_last_5_transactions", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_last_5_transactions request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_last_5_transactions = dynamic_cast<const t_mediator_command_response_get_last_5_transactions&>(*response);
		for(const auto &tx:response_get_last_5_transactions.m_last_5_transactions) {
			result.push_back(tx);
		}
		return std::make_pair( "done" , result );
	});

	add_method("get_last_5_votings", [this](const nlohmann::json &) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_last_5_votings request;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_last_5_votings = dynamic_cast<const t_mediator_command_response_get_last_5_votings&>(*response);
		for(const auto &voting:response_get_last_5_votings.m_last_5_votings) {
			nlohmann::json votings_data;
			std::string voting_id_str;
			voting_id_str.resize(hash_size*2+1);
			sodium_bin2hex(voting_id_str.data(),
			                voting_id_str.size(),
			                voting.first.data(),
			                voting.first.size());
			votings_data["voting_id"] = voting_id_str.c_str();
			votings_data["name"] = voting.second.m_name;
			bool is_waiting = false;
			for(const auto &voting_is_waiting:response_get_last_5_votings.m_is_waiting) {
				if(voting_is_waiting == voting.first) {
					votings_data["status"] = "waiting";
					is_waiting = true;
				}
			}
			if(is_waiting == false) {
				for(const auto &voting_is_finished:response_get_last_5_votings.m_is_finished) {
					if(voting_is_finished.first == voting.first) {
						if(voting_is_finished.second == true) votings_data["status"] = "finished";
						else votings_data["status"] = "active";
					}
				}
			}
			votings_data["start_time"] = voting.second.m_start_timepoint;
			votings_data["end_time"] = voting.second.m_start_timepoint +
			                            voting.second.m_number_of_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;
			for(const auto &voter_turnout: response_get_last_5_votings.m_voter_turnout) {
				if(voter_turnout.first == voting.first) votings_data["voter_turnout"] = voter_turnout.second;
			}
			votings_data["type"] = voting.second.m_voting_type;
			result.push_back(votings_data);
		}
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

	add_method("get_votings_by_name_or_id", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_votings_by_name_or_id request;
		const size_t offset = input.at("params").at("offset");
		request.m_offset = offset;
		const std::string voting_name = input.at("params").at("voting_name_or_id");
		request.m_name_or_voting_id = voting_name;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_votings_by_name_or_id = dynamic_cast<const t_mediator_command_response_get_votings_by_name_or_id&>(*response);
		result["total_number_votings"] = response_get_votings_by_name_or_id.m_total_number_votings;
		nlohmann::json votings_data;
		for(const auto &voting:response_get_votings_by_name_or_id.m_votings) {
			std::string voting_id_str;
			voting_id_str.resize(hash_size*2+1);
			sodium_bin2hex(voting_id_str.data(),
			                voting_id_str.size(),
			                voting.first.data(),
			                voting.first.size());
			votings_data["voting_id"] = voting_id_str.c_str();
			votings_data["name"] = voting.second.m_name;
			bool is_waiting = false;
			for(const auto &voting_is_waiting:response_get_votings_by_name_or_id.m_is_waiting) {
				if(voting_is_waiting == voting.first) {
					votings_data["status"] = "waiting";
					is_waiting = true;
				}
			}
			if(is_waiting == false) {
				for(const auto &voting_is_finished:response_get_votings_by_name_or_id.m_is_finished) {
					if(voting_is_finished.first == voting.first) {
						if(voting_is_finished.second == true) votings_data["status"] = "finished";
						else votings_data["status"] = "active";
					}
				}
			}
			votings_data["start_time"] = voting.second.m_start_timepoint;
			votings_data["end_time"] = voting.second.m_start_timepoint +
			                            voting.second.m_number_of_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;
			for(const auto &voter_turnout: response_get_votings_by_name_or_id.m_voter_turnout) {
				if(voter_turnout.first == voting.first) votings_data["voter_turnout"] = voter_turnout.second;
			}
			votings_data["type"] = voting.second.m_voting_type;
			votings_data["voting_question"] = voting.second.m_question;
			votings_data["authorization_level"] = voting.second.m_authorization_level;
			const auto votings_results = response_get_votings_by_name_or_id.m_votings_results;
			for(const auto &voting_result:votings_results) {
				if(voting_result.first==voting.first) {
					for(const auto &option:voting_result.second) {
						const auto &name_of_option = option.first;
						votings_data["votings_result"][name_of_option] = option.second;
					}
				}
			}
			result["votings"].push_back(votings_data);
		}
		return std::make_pair( "done" , result );
	});
	
	add_method("get_latest_votings", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_latest_votings request;
		const unsigned long number_voting = input.at("params").at("number_votings");
		request.m_amount_votings = number_voting;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_latest_votings = dynamic_cast<const t_mediator_command_response_get_latest_votings&>(*response);
		for(const auto &voting:response_get_latest_votings.m_latest_votings) {
			nlohmann::json votings_data;
			std::string voting_id_str;
			voting_id_str.resize(hash_size*2+1);
			sodium_bin2hex(voting_id_str.data(),
			                voting_id_str.size(),
			                voting.first.data(),
			                voting.first.size());
			votings_data["voting_id"] = voting_id_str.c_str();
			votings_data["name"] = voting.second.m_name;
			bool is_waiting = false;
			for(const auto &voting_is_waiting:response_get_latest_votings.m_is_waiting) {
				if(voting_is_waiting == voting.first) {
					votings_data["status"] = "waiting";
					is_waiting = true;
				}
			}
			if(is_waiting == false) {
				for(const auto &voting_is_finished:response_get_latest_votings.m_is_finished) {
					if(voting_is_finished.first == voting.first) {
						if(voting_is_finished.second == true) votings_data["status"] = "finished";
						else votings_data["status"] = "active";
					}
				}
			}
			votings_data["start_time"] = voting.second.m_start_timepoint;
			votings_data["end_time"] = voting.second.m_start_timepoint +
			                            voting.second.m_number_of_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;
			for(const auto &voter_turnout: response_get_latest_votings.m_voter_turnout) {
				if(voter_turnout.first == voting.first) votings_data["voter_turnout"] = voter_turnout.second;
			}
			votings_data["type"] = voting.second.m_voting_type;
			result.push_back(votings_data);
		}
		return std::make_pair( "done" , result );
	});
	
	add_method("get_votings_per_page", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_votings_per_page request;
		const unsigned long offset = input.at("params").at("offset");
		request.m_offset = offset;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_votings_per_page = dynamic_cast<const t_mediator_command_response_get_votings_per_page&>(*response);
		result["total_number_votings"] = response_get_votings_per_page.m_total_number_votings;
		for(const auto &voting:response_get_votings_per_page.m_votings) {
			nlohmann::json votings_data;
			std::string voting_id_str;
			voting_id_str.resize(hash_size*2+1);
			sodium_bin2hex(voting_id_str.data(),
			                voting_id_str.size(),
			                voting.first.data(),
			                voting.first.size());
			votings_data["voting_id"] = voting_id_str.c_str();
			votings_data["name"] = voting.second.m_name;
			bool is_waiting = false;
			for(const auto &voting_is_waiting:response_get_votings_per_page.m_is_waiting) {
				if(voting_is_waiting == voting.first) {
					votings_data["status"] = "waiting";
					is_waiting = true;
				}
			}
			if(is_waiting == false) {
				for(const auto &voting_is_finished:response_get_votings_per_page.m_is_finished) {
					if(voting_is_finished.first == voting.first) {
						if(voting_is_finished.second == true) votings_data["status"] = "finished";
						else votings_data["status"] = "active";
					}
				}
			}
			votings_data["start_time"] = voting.second.m_start_timepoint;
			votings_data["end_time"] = voting.second.m_start_timepoint +
			                            voting.second.m_number_of_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;
			for(const auto &voter_turnout: response_get_votings_per_page.m_voter_turnout) {
				if(voter_turnout.first == voting.first) votings_data["voter_turnout"] = voter_turnout.second;
			}
			votings_data["type"] = voting.second.m_voting_type;
			result["votings"].push_back(votings_data);
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
	
	add_method( "get_tx_with_parse_metadata", [this](const nlohmann::json & input ) -> std::pair<std::string, nlohmann::json> {
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
		const auto & response_get_tx_with_parse_metadata = dynamic_cast<const t_mediator_command_response_get_tx &>(*response_mediator);
		const auto tx = response_get_tx_with_parse_metadata.m_transaction;
		result["transaction"] = tx;

		const auto metadata_map = get_metadata_map(tx.m_allmetadata);
		if(const auto search = metadata_map.find("VN"); search != metadata_map.cend()) {
			const auto voting_name_vec = search->second;
			result["parsed_metadata"]["Voting_name"] = container_to_string(voting_name_vec).c_str();
		}
		if(const auto search = metadata_map.find("AL"); search != metadata_map.cend()) {
			const auto auth_level_vec = search->second;
			result["parsed_metadata"]["Authorization_level"] = get_integer<uint32_t>(auth_level_vec);
		}
		if(const auto search = metadata_map.find("NC"); search != metadata_map.cend()) {
			const auto number_of_chioce_vec = search->second;
			result["parsed_metadata"]["Number_of_choice"] = get_integer<uint16_t>(number_of_chioce_vec);
		}
		if(const auto search = metadata_map.find("QS"); search != metadata_map.cend()) {
			const auto question_vec = search->second;
			result["parsed_metadata"]["Question"] = container_to_string(question_vec).c_str();
		}
		if(const auto search = metadata_map.find("OP"); search != metadata_map.cend()) {
			nlohmann::json options;
			auto iterators_OP = metadata_map.equal_range("OP");
			for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
				const auto &option = iterator->second;
				const auto option_str = container_to_string(option);
				options.push_back(option_str);
			}
			result["parsed_metadata"]["Options"] = options;
		}
		uint32_t start_time = 0;
		if(const auto search = metadata_map.find("ST"); search != metadata_map.cend()) {
			const auto start_voting_time_vec = search->second;
			start_time = get_integer<uint32_t>(start_voting_time_vec);
			result["parsed_metadata"]["Start_voting_date"] = start_time;
		}
		if(const auto search = metadata_map.find("BE"); search != metadata_map.cend()) {
			const auto number_blocks_to_the_end_vec = search->second;
			const auto number_blocks_to_the_end = get_integer<uint32_t>(number_blocks_to_the_end_vec);
			const auto end_time = start_time + number_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;
			result["parsed_metadata"]["End_voting_date"] = end_time;
		}
		if(const auto search = metadata_map.find("CO"); search != metadata_map.cend()) {
			const auto color_vec = search->second;
			std::string color_str;
			color_str.resize(color_vec.size()*2+1);
			sodium_bin2hex(color_str.data(),
			                color_str.size(),
			                color_vec.data(),
			                color_vec.size());
			result["parsed_metadata"]["Voting_group/Organizer_pk"] = color_str.c_str();
		}
		if(const auto search = metadata_map.find("CP"); search != metadata_map.cend()) {
			const auto color_vec = search->second;
			std::string color_str;
			color_str.resize(color_vec.size()*2+1);
			sodium_bin2hex(color_str.data(),
			                color_str.size(),
			                color_vec.data(),
			                color_vec.size());
			result["parsed_metadata"]["Organizer_parent_pk"] = color_str.c_str();
		}
		if(const auto search = metadata_map.find("VI"); search != metadata_map.cend()) {
			const auto voting_id_vec = search->second;
			std::string voting_id_str;
			voting_id_str.resize(voting_id_vec.size()*2+1);
			sodium_bin2hex(voting_id_str.data(),
			                voting_id_str.size(),
			                voting_id_vec.data(),
			                voting_id_vec.size());
			result["parsed_metadata"]["Voting_id"] = voting_id_str.c_str();
		}
		if(const auto search = metadata_map.find("PK"); search != metadata_map.cend()) {
			const auto pk_vec = search->second;
			std::string pk_str;
			pk_str.resize(pk_vec.size()*2+1);
			sodium_bin2hex(pk_str.data(),
			                pk_str.size(),
			                pk_vec.data(),
			                pk_vec.size());
			result["parsed_metadata"]["Authorized_person_pk"] = pk_str.c_str();
		}
		if(const auto search = metadata_map.find("PD"); search != metadata_map.cend()) {
			const auto personal_data_vec = search->second;
			std::string personal_data_str;
			personal_data_str.resize(personal_data_vec.size()*2+1);
			sodium_bin2hex(personal_data_str.data(),
			                personal_data_str.size(),
			                personal_data_vec.data(),
			                personal_data_vec.size());
			result["parsed_metadata"]["Hash_of_personal_data"] = personal_data_str.c_str();
		}
		if(const auto search = metadata_map.find("VT"); search != metadata_map.cend()) {
			const auto voting_type_vec = search->second;
			result["parsed_metadata"]["Voting_type"] = get_integer<uint8_t>(voting_type_vec);
		}

		return std::make_pair( "done" , result );

	});
	
	add_method("get_voting_by_id", [this](const nlohmann::json & input) -> std::pair<std::string, nlohmann::json> {
		nlohmann::json result;
		t_mediator_command_request_get_voting_by_id request;
		const std::string voting_id_str = input.at("params").at("voting_id");
		t_hash_type voting_id;
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
		                                voting_id_str.data(), voting_id_str.size(),
		                                nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		request.m_voting_id = voting_id;
		const auto response = m_rpc_module->notify_mediator(request);
		const auto response_get_voting_by_id = dynamic_cast<const t_mediator_command_response_get_voting_by_id&>(*response);
		result["name"] = response_get_voting_by_id.m_voting_metadata.m_name;
		if(response_get_voting_by_id.m_voting_status == 'V')result["status"] = "active";
		else if(response_get_voting_by_id.m_voting_status == 'X')result["status"] = "finished";
		else result["status"] = "waiting";
		result["start_time"] = response_get_voting_by_id.m_voting_metadata.m_start_timepoint;
		result["end_time"] = response_get_voting_by_id.m_voting_metadata.m_start_timepoint +
		        response_get_voting_by_id.m_voting_metadata.m_number_of_blocks_to_the_end * n_blockchainparams::blocks_diff_time_in_sec;
		result["voter_turnout"] = response_get_voting_by_id.m_voter_turnout;
		result["type"] = response_get_voting_by_id.m_voting_metadata.m_voting_type;
		result["voting_question"] = response_get_voting_by_id.m_voting_metadata.m_question;
		result["authorization_level"] = response_get_voting_by_id.m_voting_metadata.m_authorization_level;
		for(const auto &option:response_get_voting_by_id.m_voting_results) {
			const auto &name_of_option = option.first;
			result["votings_result"][name_of_option] = option.second;
		}

		return std::make_pair( "done" , result );
	});
}
void c_rpc_exec::set_rpc_module(c_rpc_module &rpc_module) {
    m_rpc_module = &rpc_module;
}
