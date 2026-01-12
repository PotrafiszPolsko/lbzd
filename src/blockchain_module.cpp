#include "blockchain_module.hpp"
#include "params.hpp"
#include "logger.hpp"
#include "utils.hpp"
#include "adminsys.hpp"
#include "organizer.hpp"
#include "txid_generate.hpp"
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

t_public_key_type c_blockchain_module::get_my_pk() const{
	t_mediator_command_request_get_pk request_mediator;
	const auto response_mediator = notify_mediator(request_mediator);
	const auto & response_mediator_get_pk = dynamic_cast<const t_mediator_command_response_get_pk&>(*response_mediator);
	const auto & my_pk = response_mediator_get_pk.m_pk;
	return my_pk;
}

void c_blockchain_module::sign_block(c_block & block) const {
	const auto & block_hash = block.m_header.m_actual_hash;
	const auto block_signature = sign_by_main_identity(block_hash);
	block.m_header.m_all_signatures.push_back(block_signature);
}

void c_blockchain_module::miner_thread_loop() {
	const auto my_pk = get_my_pk();
	const auto am_i_admin = 
			std::any_of(
				n_blockchainparams::admins_sys_pub_keys.cbegin(),
				n_blockchainparams::admins_sys_pub_keys.cend(),
				[&my_pk](const t_public_key_type& admin_pk){return (my_pk == admin_pk);});
	// mine genesis block
	const auto force_mine = (m_force_mine && am_i_admin);
	{
		std::lock_guard<std::shared_mutex> lock(m_blockchain_mutex);
		if (n_blockchainparams::is_pk_adminsys(my_pk) && m_blockchain->get_current_height() == static_cast<size_t>(-1)) {
			c_miner_genesis miner_genesis;
			auto block_genesis = miner_genesis.mine_block();
			sign_block(block_genesis);
			add_verifyed_block_to_blockchain(block_genesis);
			broadcast_block(block_genesis);
		}
	}
	// wait for sync
	if (!force_mine) {
		const auto bc_sync_check_time = std::chrono::seconds(1);
		while (!is_blockchain_synchronized()) std::this_thread::sleep_for(bc_sync_check_time);
	}
	// start mining
	while (!m_miner_stop_flag) {
		{
			std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
			const auto last_block = m_blockchain->get_last_block();
			lock.unlock();
			const auto last_block_time = last_block.m_header.m_block_time;
			const auto end_sleep_timepoint = last_block_time + n_blockchainparams::blocks_diff_time_in_sec;
			const auto now_timepoint = get_unix_time();
			const auto seconds_to_sleep = end_sleep_timepoint - now_timepoint;
			std::this_thread::sleep_for(std::chrono::seconds(seconds_to_sleep));
		}
		std::unique_lock<std::shared_mutex> lock(m_blockchain_mutex);
		const auto number_of_active_miners = m_utxo->get_number_of_miners();
		if (m_block_tmp.has_value()) {
			bool is_block_signed_by_me = false;
			for (const auto & signature : m_block_tmp->m_header.m_all_signatures) {
				const auto & txid = m_block_tmp->m_header.m_actual_hash;
				if (n_bip32::c_key_manager_BIP32::verify(txid.data(), txid.size(), signature, my_pk) == true)
					is_block_signed_by_me = true;
			}
			if (is_block_signed_by_me) continue;
			else { // add my signature
				if (!m_block_verifyer->verify_block(*m_block_tmp)) {
					LOG(fatal) << "bad block";
					m_block_tmp.reset();
					continue;
				}
				sign_block(*m_block_tmp);
				broadcast_block(*m_block_tmp);
				if (m_block_tmp->m_header.m_all_signatures.size() < get_minimum_number_of_block_signatures(number_of_active_miners)) {
					add_verifyed_block_to_blockchain(*m_block_tmp);
					m_block_tmp.reset();
				}
			}
		} else {
			const auto last_block = m_blockchain->get_last_block();
			const auto number_of_active_miners = m_utxo->get_number_of_miners();
			auto block = m_miner->mine_block(last_block, number_of_active_miners, *m_mempool);
			sign_block(block);
			if (!m_block_verifyer->verify_block(block)) {
				LOG(fatal) << "bad block";
				throw std::runtime_error("bad block");
			}
			add_verifyed_block_to_blockchain(block);
			m_block_tmp.reset();
			broadcast_block(block);
			lock.unlock();
		}
	}
}

void c_blockchain_module::update_block_tmp(const c_block & block) {
	if (!m_block_tmp.has_value()) {
		m_block_tmp = block;
	} else if (block.m_header.m_all_signatures.size() > m_block_tmp->m_header.m_all_signatures.size()) {
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

c_blockchain_module::~c_blockchain_module() {
	if (m_miner_thread.joinable())
		m_miner_thread.join();
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
	m_utxo->update(block);
	// remove transactions from mempool
	assert(m_mempool != nullptr);
	for (const auto & tx : block.m_transaction) {
		m_mempool->remove_transaction_if_exists(tx.m_txid);
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

bool c_blockchain_module::add_new_transaction(const c_transaction & transaction) {
	{
		const auto & txid = transaction.m_txid;
		std::string txid_str;
		txid_str.resize(2*txid.size()+1);
		sodium_bin2hex(txid_str.data(), txid_str.size(), txid.data(), txid.size());
		LOG(info) << "add transaction to mempool, txid is " << txid_str;
	}
	std::lock_guard<std::shared_mutex> lock(m_blockchain_mutex);
	if (m_mempool->is_transaction_in_mempool(transaction.m_txid)) return false;
	try {
		m_blockchain->get_transaction(transaction.m_txid);
		return false; // found in blockchain so return
	} catch (const std::exception &) {}
	// not found in memool and blockchain
	return m_mempool->add_transaction(transaction, *m_utxo);
}

size_t c_blockchain_module::get_number_of_mempool_transactions() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_mempool->size();
}

std::vector<c_transaction> c_blockchain_module::get_mempool_transactions() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_mempool->get_transactions();
}

std::tuple<c_blockchain *, std::shared_mutex *, c_utxo *> c_blockchain_module::get_blockchain_ref() {
	return std::make_tuple(m_blockchain.get(), &m_blockchain_mutex, m_utxo.get());
}

void c_blockchain_module::run() {
	LOG(info) << "Run blockchain module";
	if (m_miner != nullptr) {
		m_miner_thread = std::thread(&c_blockchain_module::miner_thread_loop, this);
	}
}

void c_blockchain_module::stop() {
	m_miner_stop_flag = true;
	if (m_miner_thread.joinable()) m_miner_thread.join();
}

bool c_blockchain_module::is_pk_organizer(const t_public_key_type &pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->is_pk_organizer(pk);
}

bool c_blockchain_module::is_pk_miner(const t_public_key_type &pk) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_utxo->is_pk_miner(pk);
}

c_transaction c_blockchain_module::authorize_organizer_by_adminsys(const t_public_key_type &organizer_pk, const t_public_key_type &adminsys_pk) {
	if(is_pk_organizer(organizer_pk)) throw std::runtime_error("the organizer is already authorized");
	const auto my_pk = get_my_pk();
	if (!n_blockchainparams::is_pk_adminsys(my_pk)) throw std::runtime_error("Can't authorize organizer. I'm not admonsys");
	c_transaction tx;
	tx.m_type = t_transactiontype::authorize_organizer;
	{
		c_vout vout;
		vout.m_pkh = generate_hash(organizer_pk);
		tx.m_vout.push_back(std::move(vout));
	}
	{
		c_vin vin;
		vin.m_txid.fill(0x00);
		vin.m_pk = adminsys_pk;
		vin.m_sign.fill(0x00);
		tx.m_vin.push_back(std::move(vin));
	}
	tx.m_txid = c_txid_generate::generate_txid(tx);
	tx.m_vin.at(0).m_sign = sign_by_main_identity(tx.m_txid);
	return tx;
}

t_signature_type c_blockchain_module::sign_by_main_identity(const t_hash_type & data_to_sign) const{
	t_mediator_command_request_sign_message_by_main_identity request;
	request.m_msg = std::string_view(reinterpret_cast<const char *>(data_to_sign.data()), data_to_sign.size());
	const auto response = notify_mediator(request);
	const auto & response_sign_message_by_main_identity = dynamic_cast<const t_mediator_command_response_sign_message_by_main_identity&>(*response);
	const auto & signature = response_sign_message_by_main_identity.m_sign;
	return signature;
}

std::vector<t_signature_type> c_blockchain_module::get_signatures_per_page(const size_t offset, std::vector<t_signature_type> &block_signatures) const {
	if(offset<1) throw std::invalid_argument("signatures offset from block must be greater than 0");
	std::sort(block_signatures.begin(), block_signatures.end(),
	[](const t_signature_type & sign_1, const t_signature_type & sign_2){return sign_1 < sign_2;});
	std::vector<t_signature_type> signatures;
	if(block_signatures.size()<n_rpcparams::number_of_block_signatures_per_page) {
		std::copy(block_signatures.cbegin(), block_signatures.cend(), std::back_inserter(signatures));
	} else {
		const auto signatures_begin = (offset-1)*n_rpcparams::number_of_block_signatures_per_page;
		const auto signatures_end = signatures_begin + n_rpcparams::number_of_block_signatures_per_page;
		if(block_signatures.size()<=signatures_begin) throw std::runtime_error("signatures offset from block is too big");
		if(signatures_end<=block_signatures.size()) {
			std::copy_n(block_signatures.cbegin()+static_cast<long int>(signatures_begin), n_rpcparams::number_of_block_signatures_per_page, std::back_inserter(signatures));
		} else {
			std::copy_n(block_signatures.cbegin()+static_cast<long int>(signatures_begin), block_signatures.size()-signatures_begin, std::back_inserter(signatures));
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

size_t c_blockchain_module::get_number_of_transactions() const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_number_of_transactions();
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

t_hash_type c_blockchain_module::get_auth_txid(const t_public_key_type &pk) const {
	return m_utxo->get_auth_txid(pk);
}

c_transaction c_blockchain_module::add_voting_protocol(const std::vector<unsigned char> &voting_protocol, const t_public_key_type &organizer_pk) {
	c_transaction tx;
	tx.m_type = t_transactiontype::another_voting_protocol;
	{
		c_vin vin;
		vin.m_txid.fill(0x00);
		vin.m_pk = organizer_pk;
		vin.m_sign.fill(0x00);
		tx.m_vin.push_back(std::move(vin));
	}
	{
		c_vout vout;
		vout.m_pkh.fill(0x00);
		tx.m_vout.push_back(std::move(vout));
	}
	tx.m_allmetadata = voting_protocol;
	tx.m_txid = c_txid_generate::generate_txid(tx);
	tx.m_vin.at(0).m_sign = sign_by_main_identity(tx.m_txid);
	return tx;
}

c_transaction c_blockchain_module::get_tx_voting_protocol(const t_hash_type &hash_voting_protocol) const {
	const auto txid = m_utxo->get_voting_protocol_txid(hash_voting_protocol);
	return m_blockchain->get_transaction(txid);
}

std::vector<t_hash_type> c_blockchain_module::get_hashes_voting_protocols() const {
	return m_utxo->get_hashes_of_voting_protocols();
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

t_hash_type c_blockchain_module::get_block_id_by_txid(const t_hash_type &txid) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_block_id_by_txid(txid);
}

std::vector<t_hash_type> c_blockchain_module::get_merkle_branch(const t_hash_type &txid) const {
	std::shared_lock<std::shared_mutex> lock(m_blockchain_mutex);
	return m_blockchain->get_merkle_branch(txid);
}

c_transaction c_blockchain_module::authorize_miner_by_adminsys( const t_public_key_type &miner_pk, const t_public_key_type &adminsys_pk) {
	const auto my_pk = get_my_pk();
	if (!n_blockchainparams::is_pk_adminsys(my_pk)) throw std::runtime_error("Can't authorize miner. I'm not admonsys");
	c_transaction tx;
	tx.m_type = t_transactiontype::authorize_miner;
	{
		c_vout vout;
		vout.m_pkh = generate_hash(miner_pk);
		tx.m_vout.push_back(std::move(vout));
	}
	{
		c_vin vin;
		vin.m_txid.fill(0x00);
		vin.m_pk = adminsys_pk;
		vin.m_sign.fill(0x00);
		tx.m_vin.push_back(std::move(vin));
	}
	std::copy(miner_pk.cbegin(), miner_pk.cend(), std::back_inserter(tx.m_allmetadata));
	tx.m_txid = c_txid_generate::generate_txid(tx);
	tx.m_vin.at(0).m_sign = sign_by_main_identity(tx.m_txid);
	return tx;
}
