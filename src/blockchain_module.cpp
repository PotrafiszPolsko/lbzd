#include "blockchain_module.hpp"
#include "params.hpp"
#include "logger.hpp"
#include "utils.hpp"
#include "txid_generate.hpp"
#include "key_manager_bip32.hpp"
#include <algorithm>
#include <mutex>

c_blockchain_module::c_blockchain_module(c_mediator & mediator)
:
	c_component (mediator),
	m_blockchain(),
	m_utxo(),
	m_block_verifyer(),
	m_mempool()
{
}

void c_blockchain_module::broadcast_block(const c_block & block) const{
	t_mediator_command_request_broadcast_block mediator_request;
	mediator_request.m_block = block;
	notify_mediator(mediator_request);
}

c_block c_blockchain_module::get_block_at_height(size_t height) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_block_at_height(height);
}

c_block c_blockchain_module::get_block_at_hash(const t_hash_type & block_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_block_at_hash(block_id);
}

proto::block c_blockchain_module::get_block_at_hash_proto(const t_hash_type & block_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_block_at_hash_proto(block_id);
}

c_block c_blockchain_module::get_block_by_txid(const t_hash_type &txid) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_block_by_txid(txid);
}

c_transaction c_blockchain_module::get_transaction(const t_hash_type & txid) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_transaction(txid);
}

bool c_blockchain_module::is_transaction_in_blockchain(const t_hash_type &txid) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->is_transaction_in_blockchain(txid);
}

std::vector<proto::header> c_blockchain_module::get_headers_proto(const t_hash_type & hash_begin, const t_hash_type & hash_end) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	std::vector<proto::header> headers;
	size_t first_height;
	const auto hash_begin_zero_filled = std::all_of(hash_begin.cbegin(), hash_begin.cend(), [](unsigned char b){return (b == (0x00));});
	if (hash_begin_zero_filled)
		first_height = 0;
	else {
		first_height = m_blockchain->get_height_for_block_id(hash_begin) + 1;
	}
	const auto current_height = m_blockchain->get_current_height();
	if(first_height == 0 && current_height == 0) {
		const auto last_block = m_blockchain->get_block_at_height(0);
		auto block_hash = last_block.m_header.m_actual_hash;
		const auto header_proto = m_blockchain->get_header_proto(block_hash);
		headers.push_back(header_proto);
		return headers;
	}
	if (first_height >= current_height) return headers;
	size_t number_of_headers = 0;
	const size_t max_headers = 200;
	if (std::all_of(hash_end.cbegin(), hash_end.cend(), [](unsigned char b){return (b == (0x00));})) {
		const auto available_headers = current_height - first_height + 1; // +1 for genesis
		number_of_headers = std::min(max_headers, available_headers);
	} else {
		const auto end_height = m_blockchain->get_height_for_block_id(hash_end);
		const auto number_of_requested_headers = end_height - first_height;
		number_of_headers = std::min(max_headers, number_of_requested_headers);
	}
	// we iterate over headers backward (using m_parent_hash field) so we need to subtract 1
	// for get headers [0, N) instead (0, N] in first download
	const size_t last_height = first_height + number_of_headers - 1;
	const auto last_block = m_blockchain->get_block_at_height(last_height);
	auto block_hash = last_block.m_header.m_actual_hash;
	for (size_t i = 0; i < number_of_headers; i++) {
		const auto header_proto = m_blockchain->get_header_proto(block_hash);
		headers.insert(headers.begin(), header_proto);
		const auto & parent_hash_as_string = header_proto.m_parent_hash();
		block_hash = transform_string_to_array<hash_size>(parent_hash_as_string);
	}
	assert(headers.size() == number_of_headers);
	return headers;
}

size_t c_blockchain_module::get_height() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto current_height = m_blockchain->get_current_height();
	return current_height;
}

t_hash_type c_blockchain_module::get_last_block_hash() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto current_height = m_blockchain->get_current_height();
	if (current_height == std::size_t(-1)) {
		t_hash_type zero_hash;
		zero_hash.fill(0x00);
		return zero_hash;
	}
	const auto last_block = m_blockchain->get_last_block();
	return last_block.m_header.m_actual_hash;
}

uint32_t c_blockchain_module::get_last_block_time() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto last_block = m_blockchain->get_last_block();
	return last_block.m_header.m_block_time;
}

void c_blockchain_module::add_verifyed_block_to_blockchain(const c_block& block) {
	m_blockchain->add_block(block);
	const auto current_height = m_blockchain->get_current_height();
	m_utxo->update(block, current_height);
	// remove transactions from mempool
	assert(m_mempool != nullptr);
	for (const auto & tx : block.m_transaction) {
		m_mempool->remove_transaction_if_exists(tx.m_txid);
	}
}

void c_blockchain_module::update_block_tmp(const c_block & block) {
	if (!m_block_tmp.has_value()) {
		m_block_tmp = block;
	} else {
		assert(block.m_header.m_all_signatures.size() == m_block_tmp->m_header.m_all_signatures.size());
		auto new_block_signatures = block.m_header.m_all_signatures;
		std::sort(new_block_signatures.begin(), new_block_signatures.end());
		auto block_tmp_signatures = m_block_tmp->m_header.m_all_signatures;
		std::sort(block_tmp_signatures.begin(), block_tmp_signatures.end());
		if (block_tmp_signatures < new_block_signatures) m_block_tmp = block;
	}
}

void c_blockchain_module::add_new_block(const c_block & block) {
	LOG(info) << "Add new block";
	std::unique_lock<std::shared_mutex> lock(m_blockchain_mutex);
	if (m_blockchain->block_exists(block.m_header.m_actual_hash)) return;
	const auto number_of_active_miners = m_utxo->get_number_of_miners();
	if (block.m_header.m_all_signatures.size() < get_minimum_number_of_block_signatures(number_of_active_miners)) {
		update_block_tmp(block);
		return;
	}
	if (!m_block_verifyer->verify_block(block)) {
		LOG(fatal) << "bad block";
		return;
	}
	m_block_tmp.reset();
	add_verifyed_block_to_blockchain(block);
	lock.unlock();
	if (!is_blockchain_synchronized()) return;
}

size_t c_blockchain_module::get_number_of_mempool_transactions() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_mempool->size();
}

std::vector<c_transaction> c_blockchain_module::get_mempool_transactions() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_mempool->get_transactions();
}

std::vector<std::pair<t_hash_type, t_voting_metadata>> c_blockchain_module::get_all_votings() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_all_votings();
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_all_active_votings() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_all_active_votings();
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_all_finished_votings() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_all_finished_votings();
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_all_finished_votings_for_voter(const t_public_key_type & voter_pk) const {
	std::vector<std::pair<t_hash_type, t_voting_metadata>> all_finished_votings_for_voter;
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto all_finished_votings = m_utxo->get_all_finished_votings();
	for (const auto & [voting_id, voting_metadata] : all_finished_votings) {
		if (m_utxo->has_voter_voting_right(voting_id, voter_pk, *m_blockchain))
			all_finished_votings_for_voter.emplace_back(voting_id, voting_metadata);
	}
	return all_finished_votings_for_voter;
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_all_inactive_votings() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_all_waiting_votings();
}

std::vector<std::pair<t_hash_type, t_voting_metadata>> c_blockchain_module::get_all_active_votings_for_voter(const t_public_key_type & voter_pk) const {
	std::vector<std::pair<t_hash_type, t_voting_metadata>> all_active_votings_for_voter;
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto all_active_votings = m_utxo->get_all_active_votings();
	LOG(debug) << "All active votings: " << all_active_votings.size();
	for (const auto & [voting_id, voting_metadata] : all_active_votings) {
		if (m_utxo->has_voter_voting_right(voting_id, voter_pk, *m_blockchain))
			all_active_votings_for_voter.emplace_back(voting_id, voting_metadata);
	}
	return all_active_votings_for_voter;
}

std::tuple<c_blockchain *, std::shared_mutex *, c_utxo *> c_blockchain_module::get_blockchain_ref() {
	return std::make_tuple(m_blockchain.get(), &m_blockchain_mutex, m_utxo.get());
}

void c_blockchain_module::run() {
	LOG(info) << "Run blockchain module";
	
}

bool c_blockchain_module::is_pk_organizer(const t_public_key_type &pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->is_pk_organizer(pk);
}

bool c_blockchain_module::is_pk_issuer(const t_public_key_type &pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->is_pk_issuer(pk);
}

bool c_blockchain_module::is_pk_voter(const t_public_key_type &pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->is_pk_voter(pk);
}

std::vector<t_authorization_data> c_blockchain_module::get_authorization_data(const t_public_key_type &pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	std::vector<t_authorization_data> authorizations_data;
	const auto txids_auth = m_utxo->get_auth_txid(pk);
	for(const auto &txid_auth: txids_auth) {
		const auto tx = m_blockchain->get_transaction(txid_auth);
		t_authorization_data authorization_data;
		authorization_data.m_txid = tx.m_txid;
		if(tx.m_type==t_transactiontype::authorize_miner) authorization_data.m_type_of_transaction = t_transactiontype::authorize_miner;
		else if(tx.m_type==t_transactiontype::authorize_voter) authorization_data.m_type_of_transaction = t_transactiontype::authorize_voter;
		else if(tx.m_type==t_transactiontype::authorize_issuer) authorization_data.m_type_of_transaction = t_transactiontype::authorize_issuer;
		else if(tx.m_type==t_transactiontype::authorize_organizer) authorization_data.m_type_of_transaction = t_transactiontype::authorize_organizer;
		else throw std::runtime_error("Bad transaction type");
		if(tx.m_type==t_transactiontype::authorize_miner) {
			authorizations_data.emplace_back(authorization_data);
			return authorizations_data;
		}
		const auto metadata_map = get_metadata_map(tx.m_allmetadata);
		if (metadata_map.count("CO") != 1) throw std::runtime_error("Not found CO field in auth tx metadata");
		const auto voting_group_vec = metadata_map.find("CO")->second;
		authorization_data.m_voting_group = container_to_array_of_uchars<public_key_size>(voting_group_vec);
		authorizations_data.emplace_back(authorization_data);
	}
	return authorizations_data;
}

std::vector<c_transaction> c_blockchain_module::get_voter_auth_tx(const t_public_key_type & voter_pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto voter_auth_txids = m_utxo->get_txids_of_tx_auth_voter(voter_pk);
	std::vector<c_transaction> voter_auth_txs;
	for(const auto &voter_auth_txid:voter_auth_txids) voter_auth_txs.emplace_back(m_blockchain->get_transaction(voter_auth_txid));
	return voter_auth_txs;
}

std::vector<t_signature_type> c_blockchain_module::get_signatures_per_page(const size_t offset, std::vector<t_signature_type> &block_signatures) const {
	if(offset<1) throw std::invalid_argument("signatures offset from block must be greater than 0");
	std::sort(block_signatures.begin(), block_signatures.end(),
	[](const t_signature_type & sign_1, const t_signature_type & sign_2){return sign_1 < sign_2;});
	std::vector<t_signature_type> signatures;
	if(block_signatures.size()<n_rpcparams::number_of_block_signatures_per_page) {
		std::copy(block_signatures.cbegin(), block_signatures.cend(), std::back_inserter(signatures));
	} else {
		const auto signatures_begin = static_cast<unsigned int>((offset-1)*n_rpcparams::number_of_block_signatures_per_page);
		const auto signatures_end = signatures_begin + n_rpcparams::number_of_block_signatures_per_page;
		if(block_signatures.size()<=signatures_begin) throw std::runtime_error("signatures offset from block is too big");
		if(signatures_end<=block_signatures.size()) {
			std::copy_n(block_signatures.cbegin() + signatures_begin, n_rpcparams::number_of_block_signatures_per_page, std::back_inserter(signatures));
		} else {
			std::copy_n(block_signatures.cbegin() + signatures_begin, block_signatures.size()-signatures_begin, std::back_inserter(signatures));
		}
	}
	return signatures;
}

bool c_blockchain_module::is_blockchain_synchronized() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto last_block = m_blockchain->get_last_block();
	lock.unlock();
	const auto last_block_time = last_block.m_header.m_block_time;
	const auto current_time = get_unix_time();
	if (last_block_time < (current_time - n_blockchainparams::blocks_diff_time_in_sec)) return false;
	else return true;
}

size_t c_blockchain_module::get_number_of_miners() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_number_of_miners();
}

size_t c_blockchain_module::get_number_of_all_voters_in_group(const t_public_key_type & organizer_pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_number_voters_in_group(organizer_pk, *m_blockchain);
}

size_t c_blockchain_module::get_all_added_votes() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings = m_utxo->get_all_finished_votings();
	const auto unfinished_votings = m_utxo->get_all_active_votings();
	std::copy(unfinished_votings.cbegin(), unfinished_votings.cend(), std::back_inserter(votings));

	size_t amount = 0;
	for(const auto &voting: votings) {
		const auto create_voting_tx = get_transaction(voting.first);
		const auto metadata_map = get_metadata_map(create_voting_tx.m_allmetadata);
		auto iterators_OP = metadata_map.equal_range("OP");
		for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
			const auto &option = iterator->second;
			const auto hash_of_option_address = get_vote_option_hash(create_voting_tx, option);
			amount += get_amount_pkh(hash_of_option_address);
		}
	}
	return amount;
}

size_t c_blockchain_module::get_number_of_transactions() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_number_of_transactions();
}

std::vector<c_block_record> c_blockchain_module::get_last_5_blocks() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_last_5_blocks();
}

std::vector<c_transaction> c_blockchain_module::get_last_5_transactions() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_last_5_transactions();
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_last_5_votings() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	auto votings = get_all_votings();
	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2)
	{if(voting_1.second.m_start_timepoint > voting_2.second.m_start_timepoint) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end > voting_2.second.m_number_of_blocks_to_the_end)) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end == voting_2.second.m_number_of_blocks_to_the_end) &&
		        (voting_1.first < voting_2.first)) return true;
	else return false;});
	if(votings.size()<=5) return votings;
	std::vector<std::pair<t_hash_type, t_voting_metadata> > last_5_votings;
	std::copy_n(votings.cbegin(), 5, std::back_inserter(last_5_votings));
	return last_5_votings;
}

bool c_blockchain_module::is_active_or_finished(const t_hash_type &voting_id) const {
	if(is_voting_finished(voting_id) == false && is_voting_active(voting_id) == false) throw std::runtime_error("the voting is waiting or there is no voting");
	if(is_voting_finished(voting_id)) return true;
	else return false;
}

bool c_blockchain_module::is_waiting(const t_hash_type &voting_id) const {
	const auto all_waiting_votings = m_utxo->get_all_waiting_votings();
	bool is_waiting = false;
	for(const auto &voting: all_waiting_votings) {
		if(voting.first==voting_id) is_waiting = true;
	}
	return is_waiting;
}

std::vector<c_block_record> c_blockchain_module::get_sorted_blocks(const size_t amount_of_blocks) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_sorted_blocks(amount_of_blocks);
}

std::pair<std::vector<c_block_record>, size_t> c_blockchain_module::get_sorted_blocks_per_page(const size_t offset) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_sorted_blocks_per_page(offset);
}

std::vector<c_transaction> c_blockchain_module::get_latest_transactions(const size_t amount_txs) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_latest_transactions(amount_txs);
}

std::pair<std::vector<c_transaction>, size_t> c_blockchain_module::get_txs_per_page(const size_t offset) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_txs_per_page(offset);
}

std::pair<std::vector<std::pair<t_hash_type, t_voting_metadata>>, size_t> c_blockchain_module::get_all_votings_by_name_or_voting_id_with_number_votings(const size_t offset, const std::string &voting_name_or_id) const {
	auto votings = get_voting_by_name_or_by_id(voting_name_or_id);
	if(offset<1) throw std::invalid_argument("voting offset must be greater than 0");
	std::vector<std::pair<t_hash_type, t_voting_metadata> > votings_per_page;
	if(votings.empty()) return std::make_pair(votings_per_page, votings.size());
	const double number_of_votings = votings.size();
	const auto max_offset =std::ceil(number_of_votings/n_rpcparams::number_of_votings_per_page);
	if(offset>static_cast<size_t>(max_offset)) throw std::runtime_error("voting offset must be less");
	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2)
	{if(voting_1.second.m_start_timepoint > voting_2.second.m_start_timepoint) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end > voting_2.second.m_number_of_blocks_to_the_end)) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end == voting_2.second.m_number_of_blocks_to_the_end) &&
		        (voting_1.first < voting_2.first)) return true;
	else return false;});
	size_t end_votings = 0;
	if(offset*n_rpcparams::number_of_votings_per_page >= votings.size()) end_votings = votings.size();
	else end_votings = offset*n_rpcparams::number_of_votings_per_page;
	for(size_t i=(offset-1)*n_rpcparams::number_of_votings_per_page; i<end_votings; i++) {
		votings_per_page.emplace_back(votings.at(i));
	}
	return std::make_pair(votings_per_page, votings.size());
}

t_voting_metadata c_blockchain_module::get_voting_metadata_by_voting_id(const t_hash_type &voting_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_voting_metadata_by_voting_id(voting_id);
}

double c_blockchain_module::get_voter_turnout_from_vote(const t_hash_type &voting_id) const {
	const auto tx = get_transaction(voting_id);
	const auto metadata_map = get_metadata_map(tx.m_allmetadata);
	auto iterators_OP = metadata_map.equal_range("OP");
	size_t amount = 0;
	for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
		const auto &option = iterator->second;
		const auto hash_of_option_address = get_vote_option_hash(tx, option);
		amount += get_amount_pkh(hash_of_option_address);
	}
	const auto number_voters = get_number_of_all_voters_in_group(tx.m_vin.at(0).m_pk);
	return (amount * 100)/number_voters;
}

std::unordered_map<std::string, uint32_t> c_blockchain_module::get_voting_result(const t_hash_type &voting_id) const {
	const auto tx = get_transaction(voting_id);
	const auto metadata_map = get_metadata_map(tx.m_allmetadata);
	auto iterators_OP = metadata_map.equal_range("OP");
	std::unordered_map<std::string, uint32_t> voting_results;
	for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
		const auto &option = iterator->second;
		const auto hash_of_option_address = get_vote_option_hash(tx, option);
		const auto amount = get_amount_pkh(hash_of_option_address);
		auto option_str = container_to_string(option);
		voting_results.emplace(std::move(option_str), amount);
	}
	return voting_results;
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_voting_by_name_or_by_id(const std::string &voting_name_or_id) const {
	auto votings = get_all_voting_by_the_same_name(voting_name_or_id);
	t_hash_type voting_id;
	if(voting_name_or_id.size() != voting_id.size()*2) return votings;
	sodium_hex2bin(reinterpret_cast<unsigned char *>(voting_id.data()), voting_id.size(),
	               voting_name_or_id.data(), voting_name_or_id.size(),
	               nullptr, nullptr, nullptr);
	const auto voting_metadata = get_voting_metadata_by_voting_id(voting_id);
	if(voting_metadata.m_authorization_level == 0 &&
	        voting_metadata.m_name.empty() &&
	        voting_metadata.m_number_of_blocks_to_the_end == 0 &&
	        voting_metadata.m_number_of_choice == 0 &&
	        voting_metadata.m_options.empty() &&
	        voting_metadata.m_question.empty() &&
	        voting_metadata.m_start_timepoint == 0 &&
	        voting_metadata.m_voting_type == 0) {
		if(votings.empty()) throw std::invalid_argument("There are no votings with this name or id");
		return votings;
	}
	const auto voting = std::make_pair(voting_id, voting_metadata);
	votings.emplace_back(voting_id, voting_metadata);
	return votings;
}

unsigned char c_blockchain_module::get_voting_status(const t_hash_type &voting_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_voting_status(voting_id);
}

bool c_blockchain_module::block_exists(const t_hash_type & block_id) const {
	return m_blockchain->block_exists(block_id);
}

c_blockchain_module::c_blockchain_module(c_mediator &mediator, std::unique_ptr<c_blockchain> &&blockchain, std::unique_ptr<c_utxo> &&utxo)
    :
      c_component(mediator),
      m_blockchain(std::move(blockchain)),
      m_utxo(std::move(utxo))
{
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_all_voting_by_the_same_name(const std::string & voting_name) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto all_votings = get_all_votings();
	std::vector<std::pair<t_hash_type, t_voting_metadata> > votings;
	for(const auto &voting:all_votings) {
		if(voting.second.m_name == voting_name) votings.emplace_back(voting);
	}
	return votings;
}

std::vector<std::pair<t_hash_type, t_voting_metadata> > c_blockchain_module::get_latest_votings(const size_t amount_votings) const {
	auto votings = get_all_votings();
	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2)
	{if(voting_1.second.m_start_timepoint > voting_2.second.m_start_timepoint) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end > voting_2.second.m_number_of_blocks_to_the_end)) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end == voting_2.second.m_number_of_blocks_to_the_end) &&
		        (voting_1.first < voting_2.first)) return true;
	else return false;});
	if(votings.size()<=amount_votings) return votings;
	std::vector<std::pair<t_hash_type, t_voting_metadata> > latest_votings;
	std::copy_n(votings.cbegin(), amount_votings, std::back_inserter(latest_votings));
	return latest_votings;
}

std::pair<std::vector<std::pair<t_hash_type, t_voting_metadata>>, size_t> c_blockchain_module::get_votings_per_page(const size_t offset) const {
	if(offset<1) throw std::invalid_argument("voting offset must be greater than 0");
	auto votings = get_all_votings();
	const double number_of_votings = votings.size();
	const auto max_offset =std::ceil(number_of_votings/n_rpcparams::number_of_votings_per_page);
	if(offset>static_cast<size_t>(max_offset)) throw std::runtime_error("voting offset must be less");
	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2)
	{if(voting_1.second.m_start_timepoint > voting_2.second.m_start_timepoint) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end > voting_2.second.m_number_of_blocks_to_the_end)) return true;
	else if((voting_1.second.m_start_timepoint == voting_2.second.m_start_timepoint) &&
		        (voting_1.second.m_number_of_blocks_to_the_end == voting_2.second.m_number_of_blocks_to_the_end) &&
		        (voting_1.first < voting_2.first)) return true;
	else return false;});
	std::vector<std::pair<t_hash_type, t_voting_metadata> > votings_per_page;
	size_t end_votings = 0;
	if(offset*n_rpcparams::number_of_votings_per_page >= votings.size()) end_votings = votings.size();
	else end_votings = offset*n_rpcparams::number_of_votings_per_page;
	for(size_t i=(offset-1)*n_rpcparams::number_of_votings_per_page; i<end_votings; i++) {
		votings_per_page.emplace_back(votings.at(i));
	}
	return std::make_pair(votings_per_page, votings.size());
}

std::pair<std::vector<c_transaction>, size_t> c_blockchain_module::get_txs_from_block_per_page(const size_t offset, const t_hash_type &block_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_txs_from_block_per_page(offset, block_id);
	
}

std::pair<std::vector<std::pair<t_signature_type, t_public_key_type>>, size_t> c_blockchain_module::get_block_signatures_and_pk_miners_per_page(const size_t offset, const t_hash_type &block_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto block = m_blockchain->get_block_at_hash(block_id);
	auto signatures = block.m_header.m_all_signatures;
	const auto signatures_per_page = get_signatures_per_page(offset, signatures);
	const auto miners_public_keys = m_utxo->get_all_miners_public_keys();
	const auto actual_hash = block.m_header.m_actual_hash;
	std::vector<std::pair<t_signature_type, t_public_key_type>> sign_and_pk;
	for (const auto & signature : signatures_per_page) {
		for (const auto & public_key : miners_public_keys) {
			if(n_bip32::c_key_manager_BIP32::verify(actual_hash.data(), actual_hash.size(), signature, public_key)) {
				sign_and_pk.emplace_back(std::make_pair(signature, public_key));
				break;
			}
		}
	}
	return std::make_pair(sign_and_pk, signatures.size());
}

std::vector<std::pair<t_hash_type, bool> > c_blockchain_module::finished_or_active_votings(const std::vector<std::pair<t_hash_type, t_voting_metadata> > &votings) const {
	std::vector<std::pair<t_hash_type, bool>> are_finished;
	for(const auto &voting: votings) {
		const auto is_finished = is_active_or_finished(voting.first);
		are_finished.emplace_back(std::make_pair(voting.first, is_finished));
	}
	return are_finished;
}

std::vector<std::pair<t_hash_type, double> > c_blockchain_module::get_voter_turnout_from_specific_votes(const std::vector<std::pair<t_hash_type, t_voting_metadata> > &votings) const {
	std::vector<std::pair<t_hash_type, double>> voter_turnout;
	for(const auto &voting: votings) {
		const auto tx = get_transaction(voting.first);
		const auto metadata_map = get_metadata_map(tx.m_allmetadata);
		auto iterators_OP = metadata_map.equal_range("OP");
		size_t amount = 0;
		for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
			const auto &option = iterator->second;
			const auto hash_of_option_address = get_vote_option_hash(tx, option);
			amount += get_amount_pkh(hash_of_option_address);
		}
		const auto number_voters = get_number_of_all_voters_in_group(tx.m_vin.at(0).m_pk);
		const double freq = (amount * 100)/number_voters;
		voter_turnout.emplace_back(std::make_pair(voting.first, freq));
	}
	return voter_turnout;
}

std::vector<t_hash_type> c_blockchain_module::get_waiting_votings_ids(const std::vector<std::pair<t_hash_type, t_voting_metadata> > &votings) const {
	std::vector<t_hash_type> waiting_votings;
	for(const auto &voting: votings)
	if(is_waiting(voting.first)) waiting_votings.emplace_back(voting.first);
	return waiting_votings;
}

std::vector<std::pair<t_hash_type, std::unordered_map<std::string, uint32_t> > > c_blockchain_module::get_votings_results_from_specific_votes(const std::vector<std::pair<t_hash_type, t_voting_metadata> > &votings) const {
	std::vector<std::pair<t_hash_type, std::unordered_map<std::string, uint32_t>> >votings_results;
	for(const auto &voting: votings) {
		const auto tx = get_transaction(voting.first);
		const auto metadata_map = get_metadata_map(tx.m_allmetadata);
		auto iterators_OP = metadata_map.equal_range("OP");
		std::unordered_map<std::string, uint32_t> voting_results;
		for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
			const auto &option = iterator->second;
			const auto hash_of_option_address = get_vote_option_hash(tx, option);
			const auto amount = get_amount_pkh(hash_of_option_address);
			const auto option_str = container_to_string(option);
			voting_results.emplace(std::make_pair(option_str, amount));
		}
		votings_results.emplace_back(std::make_pair(voting.first, voting_results));
	}
	return votings_results;
}

bool c_blockchain_module::is_voting_finished(const t_hash_type &voting_id) const {
	const auto all_finished_votings = get_all_finished_votings();
	for(const auto &voting: all_finished_votings)
		if(voting.first == voting_id) return true;
	return false;
}

bool c_blockchain_module::is_voting_active(const t_hash_type &voting_id) const {
	const auto all_active_votings = get_all_active_votings();
	for(const auto &voting: all_active_votings)
		if(voting.first == voting_id) return true;
	return false;
}

size_t c_blockchain_module::get_number_of_all_voters() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_number_of_all_voters();
}

std::vector<unsigned char> c_blockchain_module::get_co_color(const std::vector<unsigned char> & allmetadata) const {
	const auto metadata_map = get_metadata_map(allmetadata);
	const auto it_CO_voter = metadata_map.find("CO");
	if(it_CO_voter==metadata_map.end()) throw std::runtime_error("Somthing wrong with authorization because there is no color");
	return it_CO_voter->second;
}

bool c_blockchain_module::is_voter_authorized_for_this_group(const std::vector<unsigned char> & co_color, const t_public_key_type & pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	if(!is_pk_voter(pk)) return false;
	const auto txids_of_tx_auth_voter = m_utxo->get_txids_of_tx_auth_voter(pk);
	for(const auto &txid_of_tx_auth_voter:txids_of_tx_auth_voter) {
		const auto tx_of_auth_voter = m_blockchain->get_transaction(txid_of_tx_auth_voter);
		const auto co_voter = get_co_color(tx_of_auth_voter.m_allmetadata);
		if(co_voter==co_color) return true;
	}
	return false;
}

t_hash_type c_blockchain_module::get_hash_personal_data(const t_public_key_type &voter_pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_hash_of_data_voter(voter_pk);
}

uint32_t c_blockchain_module::get_amount_pkh(const t_hash_type &pkh) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_amount_on_pkh(pkh);
}

t_public_key_type c_blockchain_module::get_voting_creator_pk(const t_hash_type & voting_id) const {
	const auto create_voting_tx = get_transaction(voting_id);
	auto organizer_pk = create_voting_tx.m_vin.at(0).m_pk;
	return organizer_pk;
}

t_hash_type c_blockchain_module::get_source_txid(const t_hash_type & pkh) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_source_txid(pkh);
}

std::vector<c_transaction> c_blockchain_module::get_all_vote_transactions(const t_hash_type & voting_id) const {
	const auto voting_details = get_voting_details(voting_id);
	const auto voting_start_timepoint = voting_details.m_start_timepoint;
	const auto genesis_block = m_blockchain->get_block_at_height(0);
	const auto genesis_block_time = genesis_block.m_header.m_block_time;
	const auto start_voting_block_height = (voting_start_timepoint - genesis_block_time) / n_blockchainparams::blocks_diff_time_in_sec;
	const auto current_height = get_height();
	std::vector<c_transaction> vote_transactions;
	for (size_t i = 0; i < voting_details.m_number_of_blocks_to_the_end; i++) {
		const auto height = start_voting_block_height + i;
		if (height > current_height) break;
		const auto block = get_block_at_height(height);
		for (const auto & tx : block.m_transaction) {
			if ((tx.m_type != t_transactiontype::add_open_vote) && (tx.m_type != t_transactiontype::add_secret_vote))
				continue;
			const auto metadata_map = get_metadata_map(tx.m_allmetadata);
			const auto voting_id_as_vector = metadata_map.find("VI")->second;
			t_hash_type vi;
			std::copy(voting_id_as_vector.cbegin(), voting_id_as_vector.cend(), vi.begin());
			if (vi != voting_id) continue;
			vote_transactions.push_back(tx);
		}
	}
	return vote_transactions;
}

t_hash_type c_blockchain_module::get_block_id_by_txid(const t_hash_type &txid) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_block_id_by_txid(txid);
}

std::vector<t_public_key_type> c_blockchain_module::get_voter_groups(const t_public_key_type &voter_pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_parent_list_voter(voter_pk, *m_blockchain);
}

std::vector<t_hash_type> c_blockchain_module::get_merkle_branch(const t_hash_type &txid) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_merkle_branch(txid);
}

t_voting_metadata c_blockchain_module::get_voting_details(const t_hash_type &voting_id) const {
	const auto create_voting_tx = get_transaction(voting_id);
	const auto metadata_map = get_metadata_map(create_voting_tx.m_allmetadata);
	t_voting_metadata voting_details;
	const auto it_voting_name = metadata_map.find("VN");
	if(it_voting_name==metadata_map.end()) throw std::runtime_error("voting details has not name");
	voting_details.m_name = container_to_string(it_voting_name->second);
	const auto it_question = metadata_map.find("QS");
	if(it_question==metadata_map.end()) throw std::runtime_error("voting details has not question");
	voting_details.m_question = container_to_string(it_question->second);
	const auto it_voting_options = metadata_map.equal_range("OP");
	if(it_voting_options.first==metadata_map.end()) throw std::runtime_error("voting details has not options");
	for(auto it=it_voting_options.first; it!=it_voting_options.second; ++it) {
		const auto voting_option_str = container_to_string(it->second);
		voting_details.m_options.emplace_back(voting_option_str);
	}
	const auto it_voting_number_of_choice = metadata_map.find("NC");
	if(it_voting_number_of_choice==metadata_map.end()) throw std::runtime_error("voting details has not number of choice");
	voting_details.m_number_of_choice = get_integer<uint16_t>(it_voting_number_of_choice->second);
	const auto it_authorization_level = metadata_map.find("AL");
	if(it_authorization_level==metadata_map.end()) throw std::runtime_error("voting details has not authorization level");
	voting_details.m_authorization_level = get_integer<uint32_t>(it_authorization_level->second);
	const auto it_voting_start_time_point = metadata_map.find("ST");
	if(it_voting_start_time_point==metadata_map.end()) throw std::runtime_error("voting details has not start time point");
	voting_details.m_start_timepoint = get_integer<uint32_t>(it_voting_start_time_point->second);
	const auto it_voting_number_of_blocks_to_the_end = metadata_map.find("BE");
	if(it_voting_number_of_blocks_to_the_end==metadata_map.end()) throw std::runtime_error("voting details has not number of blocks to the end");
	voting_details.m_number_of_blocks_to_the_end = get_integer<uint32_t>(it_voting_number_of_blocks_to_the_end->second);
	const auto it_voting_type = metadata_map.find("VT");
	if(it_voting_type==metadata_map.end()) throw std::runtime_error("voting details has not number of voting type");
	voting_details.m_voting_type = get_integer<uint8_t>(it_voting_type->second);
	return voting_details;
}

t_hash_type c_blockchain_module::get_vote_option_hash(const c_transaction &create_voting_tx, const std::vector<unsigned char> &option) {
	const auto voting_tx_metadata = get_metadata_map(create_voting_tx.m_allmetadata);
	const auto options_range = voting_tx_metadata.equal_range("OP");
	std::vector<std::vector<unsigned char>> voting_options;
	for (auto it = options_range.first; it != options_range.second; ++it) {
		voting_options.push_back(it->second);
	}
	const auto it = std::find(voting_options.cbegin(), voting_options.cend(), option);
	if(it==voting_options.cend()) 
		throw std::runtime_error("There is no such option to vote");
	std::vector<unsigned char> hash_input(create_voting_tx.m_txid.cbegin(), create_voting_tx.m_txid.cend());
	std::copy(option.cbegin(), option.cend(), std::back_inserter(hash_input));
	return generate_hash(hash_input);
}

bool c_blockchain_module::check_the_voter_voted(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->check_the_voter_voted(voter_pk, voting_id);
}

std::vector<t_hash_type> c_blockchain_module::get_txids_of_tx_auth_voter(const t_public_key_type & pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->get_txids_of_tx_auth_issuer(pk);
}

t_hash_type c_blockchain_module::get_voter_auth_txid_for_voting(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	const auto voting_creator_pk = get_voting_creator_pk(voting_id);
	const auto auth_txids = m_utxo->get_txids_of_tx_auth_voter(voter_pk);
	for (const auto & voter_auth_by_issuer_txid : auth_txids) {
		const auto auth_tx = m_blockchain->get_transaction(voter_auth_by_issuer_txid);
		const auto tx_co_metadata_field = get_co_color(auth_tx.m_allmetadata);
		t_public_key_type pk_from_co;
		assert(tx_co_metadata_field.size() == pk_from_co.size());
		std::copy(tx_co_metadata_field.cbegin(), tx_co_metadata_field.cend(), pk_from_co.begin());
		if (pk_from_co == voting_creator_pk)  return voter_auth_by_issuer_txid;
	}
	throw std::runtime_error("Not found auth tx for this voting");
}

void c_blockchain_module::reindex_chainstate() {
	const auto height = m_blockchain->get_current_height();
	LOG(info) << "Start reindex chainstate, current height: " << height;
	for (size_t i = 0; i <= height; i++) {
		const auto block = m_blockchain->get_block_at_height(i);
		std::string block_id_as_str;
		block_id_as_str.resize(block.m_header.m_actual_hash.size()*2+1);
		sodium_bin2hex(block_id_as_str.data(),
					   block_id_as_str.size(),
					   block.m_header.m_actual_hash.data(),
					   block.m_header.m_actual_hash.size()
					);
		if (i%100 == 0)
			LOG(info) << "Reindex block " << i << " " << block_id_as_str;
		m_utxo->update(block, i);
	}
	LOG(info) << "Reindex chainstate done";
}
