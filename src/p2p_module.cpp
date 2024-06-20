#include "p2p_module.hpp"
#include "utils.hpp"
#include "logger.hpp"
#include "serialization_utils.hpp"
#include <random>

const std::array<std::pair<std::string, unsigned short>, 3> c_p2p_module::s_seed_nodes = {
	std::make_pair(std::string("proton.ivoting.pl"), 22083),
	std::make_pair(std::string("foton.ivoting.pl"), 22083),
	std::make_pair(std::string("antyneutron.ivoting.pl"), 22083)
};

c_p2p_module::c_p2p_module(c_mediator & mediator)
:
	c_component (mediator)
{
}

void c_p2p_module::send_proto_message_to_peer(const proto::proto_massage & proto_message, const c_peer_reference& endpoint) {
	LOG(debug) << "\e[0;31m" << proto_message.DebugString() << "\e[0m";
	const std::string serialized_message = proto_message.SerializeAsString();
	const auto type = endpoint.get_type();
	if(type==c_peer_reference::type::e_tcp) m_session_manager_tcp->send_to_peer(endpoint, serialized_message);
	if(type==c_peer_reference::type::e_url) m_session_manager_tcp->send_to_peer(endpoint, serialized_message);
	if(type==c_peer_reference::type::e_onion) m_session_manager_tor->send_to_peer(endpoint, serialized_message);
}

void c_p2p_module::broadcast_proto_message(const proto::proto_massage & proto_message, const bool only_tor) {
	LOG(debug) << "\e[0;31m broadcast " << proto_message.DebugString() << "\e[0m";
	const auto proto_message_as_string = proto_message.SerializeAsString();
	if (m_session_manager_tor->number_of_connected_peers() == 0) 
		LOG(warning) << "No connected tor peers";
	m_session_manager_tor->send_to_all_peers(proto_message_as_string);
	if (!only_tor) {
		m_session_manager_tcp->send_to_all_peers(proto_message_as_string);
	}
}

void c_p2p_module::gettx_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & gettx_proto = request_proto.m_gettxs();
	const std::string txid_as_str = gettx_proto.m_hash_header();
	constexpr size_t hash_size = std::tuple_size<t_hash_type>::value;
	const t_hash_type txid = transform_string_to_array<hash_size>(txid_as_str);
	t_mediator_command_request_get_tx request_mediator;
	request_mediator.m_txid = txid;
	const auto response_mediator = notify_mediator(request_mediator);
	const auto & response_get_tx = dynamic_cast<const t_mediator_command_response_get_tx &>(*response_mediator);
	const auto tx = response_get_tx.m_transaction;
	proto::proto_massage proto_message;
	auto * const transaction_proto = proto_message.mutable_m_transaction();
	*transaction_proto = transaction_to_protobuf(tx);
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getblock_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & getblock_proto = request_proto.m_getblock();
	const std::string blockid_as_str = getblock_proto.m_hash_header();
	const t_hash_type blockid = transform_string_to_array<hash_size>(blockid_as_str);
	t_mediator_command_request_get_block_by_id_proto request_mediator;
	request_mediator.m_block_hash = blockid;
	const auto response_mediator = notify_mediator(request_mediator);
	auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_id_proto &>(*response_mediator);
	auto & block_proto = response_get_block.m_block_proto;
	// pack to message
	proto::proto_massage proto_message;
	auto * const block_proto_message = proto_message.mutable_m_block();
	block_proto_message->Swap(&block_proto);
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getheaders_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & getheaders_proto = request_proto.m_getheaders();
	const auto hash_header_start_as_str = getheaders_proto.m_hash_header_start();
	const auto hash_header_stop_as_str = getheaders_proto.m_hash_header_stop();
	const auto hash_header_start = transform_string_to_array<hash_size>(hash_header_start_as_str);
	const auto hash_header_stop = transform_string_to_array<hash_size>(hash_header_stop_as_str);
	t_mediator_command_request_get_headers_proto request_mediator;
	request_mediator.m_hash_begin = hash_header_start;
	request_mediator.m_hash_end = hash_header_stop;
	const auto response_mediator = notify_mediator(request_mediator);
	auto & response_get_headers = dynamic_cast<t_mediator_command_response_get_headers_proto &>(*response_mediator);
	proto::proto_massage proto_message;
	auto * const headers_proto = proto_message.mutable_m_headers();
	for (auto & header_proto : response_get_headers.m_headers) {
		auto * const new_header = headers_proto->add_m_headers();
		new_header->Swap(&header_proto);
	}
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getmempooltxs_request(const c_peer_reference & endpoint) {
	t_mediator_command_request_get_mempool_transactions request_mediator;
	const auto response_mediator = notify_mediator(request_mediator);
	const auto & response_get_mempool_txs = dynamic_cast<const t_mediator_command_response_get_mempool_transactions&>(*response_mediator);
	for (const auto & tx : response_get_mempool_txs.m_transactions) {
		proto::proto_massage proto_message;
		auto * const proto_tx_message = proto_message.mutable_m_transaction();
		const auto transaction_proto = transaction_to_protobuf(tx);
		proto_tx_message->CopyFrom(transaction_proto);
		send_proto_message_to_peer(proto_message, endpoint);
	}
}

void c_p2p_module::getaddr_request(const c_peer_reference & endpoint) {
	const auto peer_list = m_peer_finder->load_peers();
	proto::addr addr;
	for (const auto & peer : peer_list) {
		auto * const proto_peer_details = addr.add_m_peer_list();
		proto_peer_details->set_m_address(peer.m_external_address);
		proto_peer_details->set_m_port(peer.m_port);
		proto_peer_details->set_m_timestamp(peer.m_timestamp);
	}
	// send my address
	const auto my_address_form_port_forwarder = m_port_forwarder->get_my_public_ip();
	if (m_my_public_address_form_commandline.has_value()) {
		auto * const proto_peer_details = addr.add_m_peer_list();
		proto_peer_details->set_m_address(m_my_public_address_form_commandline->first);
		proto_peer_details->set_m_port(m_my_public_address_form_commandline->second);
		proto_peer_details->set_m_timestamp(get_unix_time());
	} else if (my_address_form_port_forwarder.has_value()) {
		auto * const proto_peer_details = addr.add_m_peer_list();
		proto_peer_details->set_m_address(my_address_form_port_forwarder->first);
		proto_peer_details->set_m_port(my_address_form_port_forwarder->second);
		proto_peer_details->set_m_timestamp(get_unix_time());
	}
	const auto tor_port = m_session_manager_tor->get_hidden_service_port();
	const auto tor_address = m_session_manager_tor->get_tor_address();
	auto * const proto_peer_details = addr.add_m_peer_list();
	proto_peer_details->set_m_address(tor_address);
	proto_peer_details->set_m_port(tor_port);
	proto_peer_details->set_m_timestamp(get_unix_time());
	proto::proto_massage proto_message;
	proto_message.mutable_m_addr()->CopyFrom(addr);
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getmerklebranch_request(const proto::request &request_proto, const c_peer_reference &endpoint) {
	const auto & getmerklebranch_proto = request_proto.m_getmerklebranch();
	const auto txid_as_str = getmerklebranch_proto.m_txid();
	proto::merkle_branch merkle_branch;
	try {
		t_mediator_command_request_get_merkle_branch request;
		request.m_txid = transform_string_to_array<hash_size>(txid_as_str);
		const auto response = notify_mediator(request);
		const auto response_get_merkle_branch = dynamic_cast<t_mediator_command_response_get_merkle_branch&>(*response);
		for(const auto & hash:response_get_merkle_branch.m_merkle_branch) {
			const auto hash_str = container_to_string(hash);
			merkle_branch.add_m_merkle_branch(hash_str);
		}
		const auto block_id_str = container_to_string(response_get_merkle_branch.m_block_id);
		merkle_branch.set_m_block_id(block_id_str);
	} catch (const std::exception & exception) {
		LOG(debug) << "exception: " << exception.what();
	}
	proto::proto_massage proto_message;
	proto_message.mutable_m_merkle_branch()->CopyFrom(merkle_branch);
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getallactivevotingsforvoter_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & get_acvtive_votings_proto = request_proto.m_get_all_active_votings_for_voter();
	const auto & voter_pk_str = get_acvtive_votings_proto.m_voter_pk();
	t_mediator_command_request_get_all_active_votings_for_voter request;
	request.m_voter_pk = transform_string_to_array<std::tuple_size<t_public_key_type>::value>(voter_pk_str);
	const auto response = notify_mediator(request);
	const auto response_get_all_votings = dynamic_cast<t_mediator_command_response_get_all_active_votings_for_voter&>(*response);
	proto::proto_massage proto_message;
	auto * const proto_active_votings = proto_message.mutable_m_all_active_votings_for_voter();
	for (const auto & voting : response_get_all_votings.m_active_votings) {
		auto * const voting_id = proto_active_votings->add_m_voting_ids();
		*voting_id = container_to_string(voting.first);
	}
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getallfinishedvotingsforvoter_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & get_finished_votings_proto = request_proto.m_get_all_finished_votings_for_voter();
	const auto & voter_pk_str = get_finished_votings_proto.m_voter_pk();
	t_mediator_command_request_get_all_finished_votings_for_voter request;
	request.m_voter_pk = transform_string_to_array<std::tuple_size<t_public_key_type>::value>(voter_pk_str);
	const auto response = notify_mediator(request);
	const auto response_get_all_votings = dynamic_cast<t_mediator_command_response_get_all_finished_votings_for_voter&>(*response);
	proto::proto_massage proto_message;
	auto * const proto_finished_votings = proto_message.mutable_m_all_finished_votings_for_voter();
	for (const auto & voting : response_get_all_votings.m_finished_votings) {
		auto * const voting_id = proto_finished_votings->add_m_voting_ids();
		*voting_id = container_to_string(voting.first);
	}
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getamountonpkh_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & get_amount_on_pkh_proto = request_proto.m_get_amount_on_pkh();
	const auto pkh_str = get_amount_on_pkh_proto.m_pkh();
	const auto pkh = transform_string_to_array<hash_size>(pkh_str);
	t_mediator_command_request_get_amount_on_pkh request;
	request.m_pkh = pkh;
	const auto response = notify_mediator(request);
	const auto & response_amount_on_pkh = dynamic_cast<const t_mediator_command_response_get_amount_on_pkh&>(*response);
	const auto amount = response_amount_on_pkh.m_amount;
	proto::proto_massage proto_message;
	auto * const proto_amount_on_pkh = proto_message.mutable_m_amount_on_pkh();
	proto_amount_on_pkh->set_m_amount(amount);
	if (amount > 0) { // get source txid
		t_mediator_command_request_get_source_txid_for_pkh request;
		request.m_pkh = pkh;
		const auto response = notify_mediator(request);
		const auto & response_source_txid = dynamic_cast<const t_mediator_command_response_get_source_txid_for_pkh&>(*response);
		proto_amount_on_pkh->set_m_txid(container_to_string(response_source_txid.m_txid));
	}
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::gettransaction_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & get_tx_proto = request_proto.m_get_transaction();
	const auto & txid_str = get_tx_proto.m_txid();
	const auto txid = transform_string_to_array<hash_size>(txid_str);
	t_mediator_command_request_get_tx request;
	request.m_txid = txid;
	const auto response = notify_mediator(request);
	const auto & response_get_tx = dynamic_cast<const t_mediator_command_response_get_tx&>(*response);
	const auto & tx =response_get_tx.m_transaction;
	const auto tx_proto = transaction_to_protobuf(tx);
	proto::proto_massage proto_message;
	auto * const proto_tx_message = proto_message.mutable_m_transaction();
	proto_tx_message->CopyFrom(tx_proto);
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::getauthtxid_request(const proto::request & request_proto, const c_peer_reference & endpoint) {
	const auto & get_auth_txid_proto = request_proto.m_get_authorization_txid();
	const auto & pk_str = get_auth_txid_proto.m_pk();
	const auto pk = transform_string_to_array<public_key_size>(pk_str);
	const auto & voting_id_str = get_auth_txid_proto.m_voting_id();
	const auto voting_id = transform_string_to_array<hash_size>(voting_id_str);
	t_mediator_command_request_get_voter_auth_txid_for_voting request;
	request.m_voter_pk = pk;
	request.m_voting_id = voting_id;
	const auto response = notify_mediator(request);
	const auto & response_txid_auth_voter = dynamic_cast<t_mediator_command_response_get_voter_auth_txid_for_voting&>(*response);
	proto::proto_massage proto_message;
	auto * const proto_tx_message = proto_message.mutable_m_authorization_txid();
	auto * const txid_str = proto_tx_message->mutable_m_txid();
	*txid_str = container_to_string(response_txid_auth_voter.m_txid);
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::parse_proto_request(const proto::request & request, const c_peer_reference & endpoint) {
	switch (request.request_type_case()) {
		case proto::request::RequestTypeCase::kMGettxs:
		{
			gettx_request(request, endpoint);
			break;
		}
		case proto::request::RequestTypeCase::kMGetblock:
			getblock_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetheaders:
			getheaders_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetmempooltransactions:
			getmempooltxs_request(endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetaddr:
			getaddr_request(endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetmerklebranch:
			getmerklebranch_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetAllActiveVotingsForVoter:
			getallactivevotingsforvoter_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetAmountOnPkh:
			getamountonpkh_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetTransaction:
			gettransaction_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetAuthorizationTxid:
			getauthtxid_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::kMGetAllFinishedVotingsForVoter:
			getallfinishedvotingsforvoter_request(request, endpoint);
			break;
		case proto::request::RequestTypeCase::REQUEST_TYPE_NOT_SET:
			break;
		default:
			break;
	}
}

void c_p2p_module::ask_for_block(const c_header & header, const c_peer_reference & endpoint) {
	const auto & block_hash = header.m_actual_hash;
	proto::proto_massage proto_message;
	auto * const proto_request = proto_message.mutable_m_request();
	auto * const proto_request_block = proto_request->mutable_m_getblock();
	const auto block_hash_as_string = container_to_string(block_hash);
	*proto_request_block->mutable_m_hash_header() = block_hash_as_string;
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::parse_proto_headers(const proto::headers & headers_proto, const c_peer_reference & endpoint) {
	if (headers_proto.m_headers_size() == 0) return;
	std::unique_lock<std::mutex> lock(m_headers_to_download_mutex);
	for (int i = 0; i < headers_proto.m_headers_size(); i++) {
		const auto & header_as_proto = headers_proto.m_headers(i);
		auto header = header_from_protobuf(header_as_proto);
		if (block_exists(header.m_actual_hash)) continue; // ignore existing block
		const auto it = std::find(m_headers_to_download.cbegin(), m_headers_to_download.cend(), header);
		if (it != m_headers_to_download.cend()) continue;
		m_headers_to_download.emplace_back(std::move(header));
	}
	if (m_headers_to_download.empty()) {
		t_mediator_command_request_is_blockchain_synchronized request;
		const auto response = notify_mediator(request);
		const auto & response_is_bc_sync = dynamic_cast<const t_mediator_command_response_is_blockchain_synchronized&>(*response);
		const auto bc_synchronized = response_is_bc_sync.m_is_blockchain_synchronized;
		if (!bc_synchronized) {
			disconnect_peer(endpoint);
			connect_to_saved_peers();
			ask_for_headers();
		} else {
			LOG(info)<<"blockchain is synchronized";
		}
		return;
	}
	const auto header = m_headers_to_download.front();
	lock.unlock();
	ask_for_block(header, endpoint);
}

void c_p2p_module::parse_proto_block(const proto::block & block_proto, const c_peer_reference & endpoint) {
	const auto & block_header_proto = block_proto.m_header();
	c_block block;
	block.m_header = header_from_protobuf(block_header_proto);
	for (int i = 0; i < block_proto.m_transaction_size(); i++) {
		const auto & transaction_proto = block_proto.m_transaction(i);
		const auto transaction = transaction_from_protobuf(transaction_proto);
		block.m_transaction.emplace_back(std::move(transaction));
	}

	t_mediator_command_request_add_new_block request_mediator;
	request_mediator.m_block = block;
	broadcast_block(block, endpoint); // send to all except endpoint
	const auto response = notify_mediator(request_mediator);
	const auto & response_add_new_block = dynamic_cast<const t_mediator_command_response_add_new_block&>(*response);
	const auto is_blockchain_synchronized = response_add_new_block.m_is_blockchain_synchronized;
	if (is_blockchain_synchronized) {
		return;
	}
	std::unique_lock<std::mutex> lock(m_headers_to_download_mutex);
	const auto now = std::chrono::system_clock::now();
	const auto diff = std::chrono::duration_cast<std::chrono::seconds>(now - m_time_to_download_headers);
	if(diff+std::chrono::seconds(60) > std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)) {
		disconnect_peer(endpoint);
		connect_to_saved_peers();
		m_headers_to_download.clear();
	}
	if(!response_add_new_block.m_is_block_exists) {
		m_headers_to_download.clear();
		ask_for_headers();
		return;
	}
	if (m_headers_to_download.empty()) {
		ask_for_headers();
		return;
	}
	m_headers_to_download.erase(m_headers_to_download.cbegin());
	if (m_headers_to_download.empty()) {
		ask_for_headers();
		return;
	}
	const auto next_header = m_headers_to_download.front();
	lock.unlock();
	ask_for_block(next_header, endpoint);
}

void c_p2p_module::parse_proto_addr(const proto::addr & addr_proto) {
	for (int i = 0; i < addr_proto.m_peer_list_size(); i++) {
		const auto & peer_details_as_proto = addr_proto.m_peer_list(i);
		std::string public_address_port = peer_details_as_proto.m_address() + ":" + std::to_string(peer_details_as_proto.m_port());
		m_peer_finder->update_peer_activity(public_address_port, peer_details_as_proto.m_timestamp());
	}
}

void c_p2p_module::parse_proto_merkle_branch(const proto::merkle_branch &merkle_branch) {
	const auto merkle_branch_str = merkle_branch.m_merkle_branch();
	LOG(debug) << "merkle branch elements: ";
	for(const auto & hash_str:merkle_branch_str) {
		const auto hash = transform_string_to_array<hash_size>(hash_str);
		std::string hash_hex_str;
		hash_hex_str.resize(hash.size()*2+1);
		sodium_bin2hex(hash_hex_str.data(), hash_hex_str.size(), hash.data(), hash.size());
		LOG(debug) << hash_hex_str;
	}
	const auto block_id_str = merkle_branch.m_block_id();
	const auto block_id = transform_string_to_array<hash_size>(block_id_str);
	std::string block_id_hex_str;
	block_id_hex_str.resize(block_id.size()*2+1);
	sodium_bin2hex(block_id_hex_str.data(), block_id_hex_str.size(), block_id.data(), block_id.size());
	LOG(debug) << "The merkle branch is from block id: " << block_id_hex_str;
}

void c_p2p_module::read_handler_tcp(const c_peer_reference & endpoint, span<const unsigned char> data) {
	m_peer_finder->update_peer_activity(endpoint);
	try {
		// protobuf
		LOG(info) << "Get tcp command from " << endpoint.to_string();
		proto::proto_massage proto_message;
		proto_message.ParseFromArray(data.data(), static_cast<int>(data.size()));
		LOG(debug) << "\e[0;34m" << proto_message.DebugString() << "\e[0m";
		switch (proto_message.message_type_case()) {
			case proto::proto_massage::MessageTypeCase::kMRequest:
			{
				parse_proto_request(proto_message.m_request(), endpoint);
				break;
			}
			case proto::proto_massage::MessageTypeCase::kMHeaders:
			{
				parse_proto_headers(proto_message.m_headers(), endpoint);
				break;
			}
			case proto::proto_massage::MessageTypeCase::kMBlock:
			{
				parse_proto_block(proto_message.m_block(), endpoint);
				break;
			}
			case proto::proto_massage::MessageTypeCase::kMAddr:
			{
				parse_proto_addr(proto_message.m_addr());
				break;
			}
			case proto::proto_massage::MessageTypeCase::kMMerkleBranch:
			{
				parse_proto_merkle_branch(proto_message.m_merkle_branch());
				break;
			}
			// ignored messages
			case proto::proto_massage::MessageTypeCase::kMTransaction:
			case proto::proto_massage::MessageTypeCase::kMAllActiveVotingsForVoter:
			case proto::proto_massage::MessageTypeCase::kMAmountOnPkh:
			case proto::proto_massage::MessageTypeCase::kMAuthorizationTxid:
			case proto::proto_massage::MessageTypeCase::kMAllFinishedVotingsForVoter:

			{
				break;
			}
			case proto::proto_massage::MessageTypeCase::MESSAGE_TYPE_NOT_SET:
			{
				throw std::runtime_error("MESSAGE_TYPE_NOT_SET");
			}
			default:
				break;
		}
	} catch (const std::exception & e) {
		LOG(error) << "read_handler_tcp error: " << e.what();
	}
}

void c_p2p_module::new_peer_handler(const c_peer_reference & endpoint) {
	{
		// ask for mempool
		proto::proto_massage proto_message;
		auto * const proto_request =  proto_message.mutable_m_request();
		auto * const proto_getmempooltransactions = proto_request->mutable_m_getmempooltransactions();
		assert(proto_getmempooltransactions->IsInitialized());
		send_proto_message_to_peer(proto_message, endpoint);
	}
	ask_for_peers(endpoint);
}

void c_p2p_module::broadcast_transaction(const c_transaction & transaction, bool only_tor) {
	const auto transaction_proto = transaction_to_protobuf(transaction);
	proto::proto_massage proto_message;
	auto * const proto_tx_message = proto_message.mutable_m_transaction();
	proto_tx_message->CopyFrom(transaction_proto);
	const auto proto_message_as_string = proto_message.SerializeAsString();
	if (m_session_manager_tor->number_of_connected_peers() == 0) 
		LOG(warning) << "No connected tor peeres";
	m_session_manager_tor->send_to_all_peers(proto_message_as_string);
	if (!only_tor) {
		m_session_manager_tcp->send_to_all_peers(proto_message_as_string);
	}
	broadcast_proto_message(proto_message, only_tor);
}

void c_p2p_module::broadcast_block(const c_block & block) {
	const auto block_proto = block_to_protobuf(block);
	proto::proto_massage proto_message;
	auto * const proto_block_message = proto_message.mutable_m_block();
	proto_block_message->CopyFrom(block_proto);
	broadcast_proto_message(proto_message);
}

void c_p2p_module::broadcast_external_ip(const std::string ip, const unsigned short port) {
	LOG(debug) << "Broadcast address " << ip << ":" << port;
	proto::proto_massage proto_message;
	auto * const proto_addr_message = proto_message.mutable_m_addr();
	auto * const peer_details = proto_addr_message->add_m_peer_list();
	peer_details->set_m_address(ip);
	peer_details->set_m_port(port);
	peer_details->set_m_timestamp(get_unix_time());
	broadcast_proto_message(proto_message);
}

bool c_p2p_module::block_exists(const t_hash_type &block_id) const {
	t_mediator_command_request_block_exists request;
	request.block_id = block_id;
	const auto response = notify_mediator(request);
	const auto & response_block_exists = dynamic_cast<const t_mediator_command_response_block_exists&>(*response);
	return response_block_exists.m_block_exists;
}

void c_p2p_module::disconnect_peer(const c_peer_reference &endpoint) {
	switch (endpoint.get_type()) {
		case c_peer_reference::type::e_onion:
		{
			m_session_manager_tor->delete_session(endpoint);
			break;
		}
		case c_peer_reference::type::e_tcp:
		{
			m_session_manager_tcp->delete_session(endpoint);
		}
		case c_peer_reference::type::e_url:
		{
			m_session_manager_tcp->delete_session(endpoint);
			break;
		}
		default:
			break;
	}
}

std::vector<std::unique_ptr<c_peer_reference>>c_p2p_module::get_peers_tcp() const {
	return m_session_manager_tcp->get_peer_list();
}

std::vector<std::unique_ptr<c_peer_reference> > c_p2p_module::get_peers_tor() const {
	return m_session_manager_tor->get_peer_list();
}

void c_p2p_module::broadcast_block(const c_block & block, const c_peer_reference & endpoint) {
	const auto block_proto = block_to_protobuf(block);
	proto::proto_massage proto_message;
	auto * const proto_block_message = proto_message.mutable_m_block();
	proto_block_message->CopyFrom(block_proto);
	const auto peer_list_tcp = m_session_manager_tcp->get_peer_list();
	for (const auto & peer_tcp : peer_list_tcp) {
		if (*peer_tcp == endpoint) continue;
		send_proto_message_to_peer(proto_message, *peer_tcp);
	}
	const auto peer_list_tor = m_session_manager_tor->get_peer_list();
	for (const auto & peer_tor : peer_list_tor) {
		if (*peer_tor == endpoint) continue;
		send_proto_message_to_peer(proto_message, *peer_tor);
	}
}

void c_p2p_module::new_identity_tor() {
	m_session_manager_tor->new_identity();
	const auto peer_list = m_peer_finder->load_peers();
	for (const auto & peer : peer_list) {
		if (peer.m_external_address.find(".onion") != std::string::npos)
			connect_to_peer(peer.m_external_address, peer.m_port);
	}
}

void c_p2p_module::ask_for_headers() {
	m_time_to_download_headers = std::chrono::system_clock::now();
	// get last block hash
	t_mediator_command_request_get_last_block_hash mediator_request;
	const auto mediator_response = notify_mediator(mediator_request);
	const auto & mediator_response_last_block_hash = dynamic_cast<const t_mediator_command_response_get_last_block_hash&>(*mediator_response);
	const auto last_block_hash = mediator_response_last_block_hash.m_last_block_hash;
	proto::proto_massage proto_message;
	auto * const proto_request =  proto_message.mutable_m_request();
	auto * const proto_getheaders = proto_request->mutable_m_getheaders();
	proto_getheaders->set_m_version(0);
	proto_getheaders->set_m_hash_header_start(container_to_string(last_block_hash)); // get headers from last block
	t_hash_type stop_hash;
	stop_hash.fill(0x00);
	proto_getheaders->set_m_hash_header_stop(container_to_string(stop_hash));
	broadcast_proto_message(proto_message);
}

void c_p2p_module::ask_for_mempool() {
	proto::proto_massage proto_message;
	auto * const proto_request =  proto_message.mutable_m_request();
	auto * const proto_getmempooltransactions = proto_request->mutable_m_getmempooltransactions();
	assert(proto_getmempooltransactions->IsInitialized());
	broadcast_proto_message(proto_message);
}

void c_p2p_module::ask_for_peers(const c_peer_reference & endpoint) {
	proto::proto_massage proto_message;
	auto * const proto_request =  proto_message.mutable_m_request();
	auto * const getaddr_proto_ptr = proto_request->mutable_m_getaddr();
	proto::getaddr getaddr_proto;
	getaddr_proto_ptr->CopyFrom(getaddr_proto);
	send_proto_message_to_peer(proto_message, endpoint);
}

void c_p2p_module::start_port_forwarding(const unsigned short port) {
	m_port_forwarder->start(port);
}

void c_p2p_module::connect_to_peer(const std::string & ip_str, unsigned short port) {
	const auto peer_address_as_str = ip_str + ':' + std::to_string(port);
	for (size_t i = 0; i < 3; i++) {
		LOG(debug) << "Connect to " << peer_address_as_str;
		if (m_peer_finder->is_peer_blacklisted(peer_address_as_str)) return;
		if (m_peer_finder->is_my_address(peer_address_as_str)) return;
		try {
			const auto peer_reference = create_peer_reference(ip_str, port);
			switch (peer_reference->get_type()) {
				case c_peer_reference::type::e_onion:
				{
					m_session_manager_tor->add_peer(*peer_reference);
					break;
				}
				case c_peer_reference::type::e_tcp:
				{
					m_session_manager_tcp->add_peer(*peer_reference);
				}
				case c_peer_reference::type::e_url:
				{
					m_session_manager_tcp->add_peer(*peer_reference);
					break;
				}
				default:
					break;
			}
			ask_for_peers(*peer_reference);
			m_peer_finder->assign_local_reference_to_external_address(*peer_reference, peer_address_as_str);
			return;
		} catch (const std::exception & exception) {
			LOG(debug) << "connect to peer error: " << exception.what();
		}
	}
	LOG(debug) << "add peer " << peer_address_as_str << " to blacklist";
	m_peer_finder->set_peer_blacklist(peer_address_as_str);
}

bool c_p2p_module::am_i_seed_node() const {
	if (m_my_public_address_form_commandline.has_value()) {
		if (std::count(s_seed_nodes.cbegin(), s_seed_nodes.cend(), *m_my_public_address_form_commandline) == 1)
			return true;
	}
	return false;
}

void c_p2p_module::connect_to_saved_peers() {
	auto peer_list = m_peer_finder->load_peers();
	std::random_device rd;
	std::mt19937 g(rd());
	std::shuffle(peer_list.begin(), peer_list.end(), g);
	LOG(debug) << "Connect to " << peer_list.size() << " saved peers";
	for (const auto & peer: peer_list) {
		const auto & ip_str = peer.m_external_address;
		const auto port = peer.m_port;
		try {
			connect_to_peer(ip_str, port);
			return;
		} catch (const std::exception & e) {
			LOG(debug) << "Connect error: " << e.what();
		}
	}
}

size_t c_p2p_module::number_of_connected_peers() const {
	return m_session_manager_tcp->number_of_connected_peers() + m_session_manager_tor->number_of_connected_peers();
}

void c_p2p_module::connect_to_random_seed_node() {
	// disable connection to seed nodes when I am seed node
	if (am_i_seed_node()) return;
	while (number_of_connected_peers() == 0) {
		try {
			std::random_device random_device;
			std::mt19937 generator(random_device());
			std::uniform_int_distribution<size_t> distribution(0, s_seed_nodes.size() - 1);
			const size_t seed_node_number = distribution(generator);
			const auto & seed_node_address = s_seed_nodes.at(seed_node_number);
			connect_to_peer(seed_node_address.first, seed_node_address.second);
			boost::asio::io_context io_context;
			boost::asio::ip::tcp::resolver resolver(io_context);
			boost::asio::ip::tcp::resolver::query query(seed_node_address.first, std::to_string(seed_node_address.second));
			boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
			c_peer_reference_url endpoint(it->endpoint());
			ask_for_peers(endpoint);
			break;
		} catch(const std::exception & e) {
			LOG(debug) << e.what();
			LOG(debug) << "Sleep for " << n_networkparams::sleep_to_connect_node <<" s";
			std::this_thread::sleep_for(std::chrono::seconds(n_networkparams::sleep_to_connect_node));
		}
	}
}

void c_p2p_module::run() {
	LOG(info) << "Run p2p module";
	LOG(info) << "Tor address: " << m_session_manager_tor->get_tor_address();
	ask_for_headers();
	ask_for_mempool();
}
