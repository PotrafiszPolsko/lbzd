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
		case t_mediator_cmd_type::e_get_voter_auth_data:
		{
			const auto & request_auth_data = dynamic_cast<const t_mediator_command_request_get_voter_auth_data&>(request);
			const auto & pk_voter = request_auth_data.m_pk_voter;
			const auto & txs_of_voter_auth = m_blockchain_module->get_voter_auth_tx(pk_voter);
			if(txs_of_voter_auth.empty()) throw std::invalid_argument("this pk is not authorized");
			std::map<t_public_key_type, uint32_t> auth_data;
			for(const auto &tx_of_voter_auth:txs_of_voter_auth) {
				const auto & all_metadata = tx_of_voter_auth.m_allmetadata;
				const auto & metadata_map = get_metadata_map(all_metadata);
				const auto auth_level_vec = metadata_map.find("AL")->second;
				const auto auth_level = get_integer<uint32_t>(auth_level_vec);
				const auto co_color = metadata_map.find("CO")->second;
				auth_data.emplace(container_to_array_of_uchars<public_key_size>(co_color), auth_level);
			}
			response = std::make_unique<t_mediator_command_response_get_voter_auth_data>();
			auto & response_auth_level = dynamic_cast<t_mediator_command_response_get_voter_auth_data&>(*response);
			response_auth_level.m_auth_level = auth_data;
			break;
		}
		case t_mediator_cmd_type::e_get_personal_data:
		{
			const auto & request_personal_data = dynamic_cast<const t_mediator_command_request_get_personal_data&>(request);
			const auto & pk_voter = request_personal_data.m_pk_voter;
			if(!m_blockchain_module->is_pk_voter(pk_voter)) throw std::invalid_argument("Bad public key");
			const auto hash_personal_data = m_blockchain_module->get_hash_personal_data(pk_voter);
			response = std::make_unique<t_mediator_command_response_get_personal_data>();
			auto & response_get_personal_data = dynamic_cast<t_mediator_command_response_get_personal_data&>(*response);
			response_get_personal_data.m_hash_personal_data = hash_personal_data;
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
		case t_mediator_cmd_type::e_get_voting_results:
		{
			const auto &request_get_txid = dynamic_cast<const t_mediator_command_request_get_voting_results&>(request);
			const auto &txid = request_get_txid.m_txid_create_voting;
			const auto tx = m_blockchain_module->get_transaction(txid);
			const auto metadata_map = get_metadata_map(tx.m_allmetadata);
			auto iterators_OP = metadata_map.equal_range("OP");
			std::unordered_map<std::string, uint32_t> voting_results;
			for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
				const auto &option = iterator->second;
				const auto hash_of_option_address = c_blockchain_module::get_vote_option_hash(tx, option);
				const auto amount = m_blockchain_module->get_amount_pkh(hash_of_option_address);
				const auto option_str = container_to_string(option);
				voting_results.emplace(std::make_pair(option_str, amount));
			}
			response = std::make_unique<t_mediator_command_response_get_voting_results>();
			auto & response_get_voting_results = dynamic_cast<t_mediator_command_response_get_voting_results&>(*response);
			const auto number_voters = m_blockchain_module->get_number_of_all_voters_in_group(tx.m_vin.at(0).m_pk);
			response_get_voting_results.m_number_of_authorized_voters = number_voters;
			response_get_voting_results.m_voting_results = std::move(voting_results);
			auto iterator_VN = metadata_map.find("VN");
			const auto &name_bin = iterator_VN->second;
			const auto name_str = container_to_string(name_bin);
			response_get_voting_results.m_voting_name = name_str;
			auto iterator_QS = metadata_map.find("QS");
			const auto question_bin = iterator_QS->second;
			const auto question_str = container_to_string(question_bin);
			response_get_voting_results.m_question = question_str;
			break;
		}
		case t_mediator_cmd_type::e_is_authorized:
		{
			const auto &request_is_authorized = dynamic_cast<const t_mediator_command_request_is_authorized&>(request);
			const auto &pk = request_is_authorized.m_pk;
			response = std::make_unique<t_mediator_command_response_is_authorized>();
			auto &response_is_authorized = dynamic_cast<t_mediator_command_response_is_authorized&>(*response);
			if(n_blockchainparams::is_pk_adminsys(pk)) {
				response_is_authorized.m_is_adminsys = true;
				break;
			}
			response_is_authorized.m_is_adminsys = false;
			response_is_authorized.m_auth_data = m_blockchain_module->get_authorization_data(pk);
			break;
		}
		case t_mediator_cmd_type::e_get_all_active_votings_for_voter:
		{
			const auto & request_get_votings = dynamic_cast<const t_mediator_command_request_get_all_active_votings_for_voter&>(request);
			const auto & voter_pk = request_get_votings.m_voter_pk;
			response = std::make_unique<t_mediator_command_response_get_all_active_votings_for_voter>();
			auto & response_get_votings = dynamic_cast<t_mediator_command_response_get_all_active_votings_for_voter&>(*response);
			response_get_votings.m_active_votings = m_blockchain_module->get_all_active_votings_for_voter(voter_pk);
			break;
		}
		case t_mediator_cmd_type::e_get_amount_on_pkh:
		{
			const auto & request_get_amount = dynamic_cast<const t_mediator_command_request_get_amount_on_pkh&>(request);
			const auto & pkh = request_get_amount.m_pkh;
			response = std::make_unique<t_mediator_command_response_get_amount_on_pkh>();
			auto & response_get_pkh = dynamic_cast<t_mediator_command_response_get_amount_on_pkh&>(*response);
			response_get_pkh.m_amount = m_blockchain_module->get_amount_pkh(pkh);
			break;
		}
		case t_mediator_cmd_type::e_check_voter_voted:
		{
			const auto & request_check_vote_voted = dynamic_cast<const t_mediator_command_request_check_voter_voted&>(request);
			const auto voter_pk = request_check_vote_voted.m_voter_pk;
			const auto voting_id = request_check_vote_voted.m_voting_id;
			response = std::make_unique<t_mediator_command_response_check_voter_voted>();
			auto & response_check_voter_voted = dynamic_cast<t_mediator_command_response_check_voter_voted&>(*response);
			response_check_voter_voted.m_voter_voted = m_blockchain_module->check_the_voter_voted(voter_pk, voting_id);
			break;
		}
		case t_mediator_cmd_type::e_get_voter_auth_txid_for_voting:
		{
			const auto & request_get_voter_auth_txid = dynamic_cast<const t_mediator_command_request_get_voter_auth_txid_for_voting&>(request);
			const auto & voter_pk = request_get_voter_auth_txid.m_voter_pk;
			const auto & voting_id = request_get_voter_auth_txid.m_voting_id;
			response = std::make_unique<t_mediator_command_response_get_voter_auth_txid_for_voting>();
			auto & response_get_voter_auth_txid = dynamic_cast<t_mediator_command_response_get_voter_auth_txid_for_voting&>(*response);
			response_get_voter_auth_txid.m_txid = m_blockchain_module->get_voter_auth_txid_for_voting(voter_pk, voting_id);
			break;
		}
		case t_mediator_cmd_type::e_get_voting_details:
		{
			const auto & request_voting_id = dynamic_cast<const t_mediator_command_request_get_voting_details&>(request);
			const auto & voting_id = request_voting_id.m_voting_id;
			response = std::make_unique<t_mediator_command_response_get_voting_details>();
			auto & response_voting_details = dynamic_cast<t_mediator_command_response_get_voting_details&>(*response);
			const auto voting_details = m_blockchain_module->get_voting_details(voting_id);
			response_voting_details.m_voting_details = voting_details;
			break;
		}
		case t_mediator_cmd_type::e_get_source_txid_for_pkh:
		{
			const auto & request_get_txid = dynamic_cast<const t_mediator_command_request_get_source_txid_for_pkh&>(request);
			const auto & pkh = request_get_txid.m_pkh;
			const auto txid = m_blockchain_module->get_source_txid(pkh);
			response = std::make_unique<t_mediator_command_response_get_source_txid_for_pkh>();
			auto & response_get_txid = dynamic_cast<t_mediator_command_response_get_source_txid_for_pkh&>(*response);
			response_get_txid.m_txid = txid;
			break;
		}
		case t_mediator_cmd_type::e_get_peers:
		{
			response = std::make_unique<t_mediator_command_response_get_peers>();
			auto & response_get_peers = dynamic_cast<t_mediator_command_response_get_peers&>(*response);
			response_get_peers.m_peers_tcp = m_p2p_module->get_peers_tcp();
			response_get_peers.m_peers_tor = m_p2p_module->get_peers_tor();
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
		case t_mediator_cmd_type::e_get_all_vote_transactions:
		{
			const auto request_get_all_vote_transactions = dynamic_cast<const t_mediator_command_request_get_all_vote_transactions&>(request);
			const auto voting_id = request_get_all_vote_transactions.m_voting_id;
			auto transactions = m_blockchain_module->get_all_vote_transactions(voting_id);
			response = std::make_unique<t_mediator_command_response_get_all_vote_transactions>();
			auto & response_get_txs = dynamic_cast<t_mediator_command_response_get_all_vote_transactions&>(*response);
			response_get_txs.m_vote_transactions = std::move(transactions);
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
		case t_mediator_cmd_type::e_get_voter_groups:
		{
			const auto request_get_voter_groups = dynamic_cast<const t_mediator_command_request_get_voter_groups&>(request);
			const auto voter_pk = request_get_voter_groups.m_voter_pk;
			const auto voter_groups = m_blockchain_module->get_voter_groups(voter_pk);
			response = std::make_unique<t_mediator_command_response_get_voter_groups>();
			auto & response_get_voter_groups = dynamic_cast<t_mediator_command_response_get_voter_groups&>(*response);
			response_get_voter_groups.m_voter_groups = voter_groups;
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_all_voters:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_voters>();
			auto & get_number_voters_data_response = dynamic_cast<t_mediator_command_response_get_number_of_all_voters&>(*response);
			get_number_voters_data_response.m_number_of_all_voters = m_blockchain_module->get_number_of_all_voters();
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_miners:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_miners>();
			auto & get_number_of_miners_response = dynamic_cast<t_mediator_command_response_get_number_of_miners&>(*response);
			get_number_of_miners_response.m_number_of_miners = m_blockchain_module->get_number_of_miners();
			break;
		}
		case t_mediator_cmd_type::e_get_all_active_voting_ids:
		{
			response = std::make_unique<t_mediator_command_response_get_all_active_voting_ids>();
			auto & get_all_active_voting_ids = dynamic_cast<t_mediator_command_response_get_all_active_voting_ids&>(*response);
			const auto votings = m_blockchain_module->get_all_active_votings();
			// transform pair <voting_id, voting_metarata> to vector<voting_id>
			std::transform(
						votings.cbegin(),
						votings.cend(),
						std::back_inserter(get_all_active_voting_ids.m_voting_ids),
						[](const std::pair<t_hash_type, t_voting_metadata> & pair){return pair.first;});
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_all_votings:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_votings>();
			auto & get_number_of_all_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_votings&>(*response);
			get_number_of_all_votings.m_number_of_all_votings = m_blockchain_module->get_all_votings().size();
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_all_inactive_votings:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_inactive_votings>();
			auto & get_number_of_inactive_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_inactive_votings&>(*response);
			get_number_of_inactive_votings.m_number_of_all_inactive_votings = m_blockchain_module->get_all_inactive_votings().size();
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_all_added_votes:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_added_votes>();
			auto & get_number_of_all_added_votes = dynamic_cast<t_mediator_command_response_get_number_of_all_added_votes&>(*response);
			get_number_of_all_added_votes.m_number_of_all_added_votes = m_blockchain_module->get_all_added_votes();
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_all_transactions:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_transactions>();
			auto & get_number_of_all_transactions = dynamic_cast<t_mediator_command_response_get_number_of_all_transactions&>(*response);
			get_number_of_all_transactions.m_number_of_all_transactions = m_blockchain_module->get_number_of_transactions();
			break;
		}
		case t_mediator_cmd_type::e_get_last_5_blocks:
		{
			response = std::make_unique<t_mediator_command_response_get_last_5_blocks>();
			auto & get_last_5_blocks = dynamic_cast<t_mediator_command_response_get_last_5_blocks&>(*response);
			get_last_5_blocks.m_last_5_blocks = m_blockchain_module->get_last_5_blocks();
			break;
		}
		case t_mediator_cmd_type::e_get_last_5_transactions:
		{
			response = std::make_unique<t_mediator_command_response_get_last_5_transactions>();
			auto & get_last_5_transactions = dynamic_cast<t_mediator_command_response_get_last_5_transactions&>(*response);
			get_last_5_transactions.m_last_5_transactions = m_blockchain_module->get_last_5_transactions();
			break;
		}
		case t_mediator_cmd_type::e_get_last_5_votings:
		{
			response = std::make_unique<t_mediator_command_response_get_last_5_votings>();
			auto & get_last_5_votings = dynamic_cast<t_mediator_command_response_get_last_5_votings&>(*response);
			get_last_5_votings.m_last_5_votings = m_blockchain_module->get_last_5_votings();
			get_last_5_votings.m_is_finished = m_blockchain_module->finished_or_active_votings(get_last_5_votings.m_last_5_votings);
			get_last_5_votings.m_voter_turnout = m_blockchain_module->get_voter_turnout_from_specific_votes(get_last_5_votings.m_last_5_votings);
			get_last_5_votings.m_is_waiting = m_blockchain_module->get_waiting_votings_ids(get_last_5_votings.m_last_5_votings);
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
		case t_mediator_cmd_type::e_get_votings_by_name_or_id:
		{
			const auto & request_get_votings_by_name = dynamic_cast<const t_mediator_command_request_get_votings_by_name_or_id&>(request);
			response = std::make_unique<t_mediator_command_response_get_votings_by_name_or_id>();
			auto & get_votings_by_name_with_number_votings = dynamic_cast<t_mediator_command_response_get_votings_by_name_or_id&>(*response);
			const auto &votings_by_name_with_number_votings = 
			        m_blockchain_module->get_all_votings_by_name_or_voting_id_with_number_votings(request_get_votings_by_name.m_offset, request_get_votings_by_name.m_name_or_voting_id);
			get_votings_by_name_with_number_votings.m_votings = votings_by_name_with_number_votings.first;
			get_votings_by_name_with_number_votings.m_is_finished = m_blockchain_module->finished_or_active_votings(get_votings_by_name_with_number_votings.m_votings);
			get_votings_by_name_with_number_votings.m_is_waiting = m_blockchain_module->get_waiting_votings_ids(get_votings_by_name_with_number_votings.m_votings);
			get_votings_by_name_with_number_votings.m_voter_turnout = m_blockchain_module->get_voter_turnout_from_specific_votes(get_votings_by_name_with_number_votings.m_votings);
			get_votings_by_name_with_number_votings.m_votings_results = m_blockchain_module->get_votings_results_from_specific_votes(get_votings_by_name_with_number_votings.m_votings);
			get_votings_by_name_with_number_votings.m_total_number_votings = votings_by_name_with_number_votings.second;
			break;
		}
		case t_mediator_cmd_type::e_get_latest_votings:
		{
			const auto & request_get_latest_voting = dynamic_cast<const t_mediator_command_request_get_latest_votings&>(request);
			response = std::make_unique<t_mediator_command_response_get_latest_votings>();
			auto & get_latest_votings = dynamic_cast<t_mediator_command_response_get_latest_votings&>(*response);
			get_latest_votings.m_latest_votings = m_blockchain_module->get_latest_votings(request_get_latest_voting.m_amount_votings);
			get_latest_votings.m_is_finished = m_blockchain_module->finished_or_active_votings(get_latest_votings.m_latest_votings);
			get_latest_votings.m_is_waiting = m_blockchain_module->get_waiting_votings_ids(get_latest_votings.m_latest_votings);
			get_latest_votings.m_voter_turnout = m_blockchain_module->get_voter_turnout_from_specific_votes(get_latest_votings.m_latest_votings);
			break;
		}
		case t_mediator_cmd_type::e_get_votings_per_page:
		{
			const auto & request_get_votings_per_page = dynamic_cast<const t_mediator_command_request_get_votings_per_page&>(request);
			const auto votings_with_total_number = m_blockchain_module->get_votings_per_page(request_get_votings_per_page.m_offset);
			response = std::make_unique<t_mediator_command_response_get_votings_per_page>();
			auto & get_votings_per_page = dynamic_cast<t_mediator_command_response_get_votings_per_page&>(*response);
			get_votings_per_page.m_votings = votings_with_total_number.first;
			get_votings_per_page.m_is_finished = m_blockchain_module->finished_or_active_votings(get_votings_per_page.m_votings);
			get_votings_per_page.m_is_waiting = m_blockchain_module->get_waiting_votings_ids(get_votings_per_page.m_votings);
			get_votings_per_page.m_voter_turnout = m_blockchain_module->get_voter_turnout_from_specific_votes(get_votings_per_page.m_votings);
			get_votings_per_page.m_total_number_votings = votings_with_total_number.second;
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
		case t_mediator_cmd_type::e_get_number_of_all_active_votings:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_active_votings>();
			auto & get_number_of_active_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_active_votings&>(*response);
			get_number_of_active_votings.m_number_of_all_active_votings = m_blockchain_module->get_all_active_votings().size();
			break;
		}
		case t_mediator_cmd_type::e_get_number_of_all_finished_votings:
		{
			response = std::make_unique<t_mediator_command_response_get_number_of_all_finished_votings>();
			auto & get_number_of_finished_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_finished_votings&>(*response);
			get_number_of_finished_votings.m_number_of_all_finished_votings = m_blockchain_module->get_all_finished_votings().size();
			break;
		}
		case t_mediator_cmd_type::e_get_voting_by_id:
		{
			const auto & request_get_voting_by_id = dynamic_cast<const t_mediator_command_request_get_voting_by_id&>(request);
			response = std::make_unique<t_mediator_command_response_get_voting_by_id>();
			auto & get_voting_by_id = dynamic_cast<t_mediator_command_response_get_voting_by_id&>(*response);
			get_voting_by_id.m_voting_metadata = m_blockchain_module->get_voting_details(request_get_voting_by_id.m_voting_id);
			get_voting_by_id.m_voter_turnout = m_blockchain_module->get_voter_turnout_from_vote(request_get_voting_by_id.m_voting_id);
			get_voting_by_id.m_voting_results = m_blockchain_module->get_voting_result(request_get_voting_by_id.m_voting_id);
			get_voting_by_id.m_voting_status = m_blockchain_module->get_voting_status(request_get_voting_by_id.m_voting_id);
			break;
		}
		case t_mediator_cmd_type::e_get_all_finished_votings_for_voter:
		{
			const auto & request_get_votings = dynamic_cast<const t_mediator_command_request_get_all_finished_votings_for_voter&>(request);
			const auto & voter_pk = request_get_votings.m_voter_pk;
			response = std::make_unique<t_mediator_command_response_get_all_finished_votings_for_voter>();
			auto & response_get_votings = dynamic_cast<t_mediator_command_response_get_all_finished_votings_for_voter&>(*response);
			response_get_votings.m_finished_votings = m_blockchain_module->get_all_finished_votings_for_voter(voter_pk);
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
			const auto & block_id = request_block_exists.block_id;
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
	m_rpc_module->run();
	m_p2p_module->run();
	std::unique_lock<std::mutex> lock(m_stop_cv_mutex);
	m_stop_cv.wait(lock, [this]{return m_stopped;});
}

void c_main_module::stop() {
	std::unique_lock<std::mutex> lock(m_stop_cv_mutex);
	m_stopped = true;
	lock.unlock();
	m_stop_cv.notify_one();
}
