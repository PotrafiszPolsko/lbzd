#include "block_verifier.hpp"
#include "params.hpp"
#include "merkle_tree.hpp"
#include "txid_generate.hpp"
#include "utils.hpp"
#include "blockchain_utils.hpp"
#include "key_manager_bip32.hpp"
#include <algorithm>
#include <future>

c_block_verifier::c_block_verifier(const c_blockchain & blockchain, const c_utxo & utxo, const size_t number_threads)
:
	m_blockchain(blockchain),
	m_utxo(utxo),
	m_number_of_threads(number_threads)
{
}

bool c_block_verifier::verify_block(const c_block & block) const {
	if (!check_parent_hash(block)) {
		return false;
	}
	if (!is_genesis(block)) {
		if (!check_time_diff(block)) return false;
		if (!check_transaction_merkle_root(block)){
			return false;
		}
	}
	if (!check_txids(block)) {
		return false;
	}
	if (!check_signatures(block)){
		return false;
	}
	if (!check_transactions(block)){
		return false;
	}
	if (!check_actual_hash(block)){
		return false;
	}
	return true;
}

bool c_block_verifier::check_parent_hash(const c_block & block) const {
	if (is_genesis(block)) {
		// genesis
		const auto & parent_hash = block.m_header.m_parent_hash;
		const bool is_zero_filled = std::all_of(parent_hash.begin(),
												parent_hash.end(),
												[](unsigned char byte) {
													return (byte == (0x00));
												}
		);
		if (!is_zero_filled) return false;
		
	} else {
		const auto parent_block = m_blockchain.get_last_block();
		const auto parent_hash = parent_block.m_header.m_actual_hash;
		if (parent_hash != block.m_header.m_parent_hash) 
			return false;
	}
	return true;
}

bool c_block_verifier::check_time_diff(const c_block & block) const {
	const auto parent_block = m_blockchain.get_last_block();
	const auto parent_time = parent_block.m_header.m_block_time;
	const auto block_time = block.m_header.m_block_time;
	if (parent_time > block_time) return false;
	const auto time_diff = block_time - parent_time;
	if (time_diff > (n_blockchainparams::blocks_diff_time_in_sec + n_blockchainparams::block_diff_time_deviation_in_sec)) {
		size_t valid_admin_signatures = 0;
		const auto actual_hash = block.m_header.m_actual_hash;
		for (const auto & signature : block.m_header.m_all_signatures) {
			for (const auto & public_key : n_blockchainparams::admins_sys_pub_keys) {
				const auto signature_ok = n_bip32::c_key_manager_BIP32::verify(actual_hash.data(), actual_hash.size(), signature, public_key);
				if (signature_ok) {
					valid_admin_signatures++;
					break;
				}
			}
		}
		if (valid_admin_signatures > 0) return true;
	}
	if ( (time_diff < n_blockchainparams::blocks_diff_time_in_sec - n_blockchainparams::block_diff_time_deviation_in_sec) ||
	   (time_diff > n_blockchainparams::blocks_diff_time_in_sec + n_blockchainparams::block_diff_time_deviation_in_sec) ) return false;
	return true;
}

bool c_block_verifier::check_transaction_merkle_root(const c_block & block) const {
	if (block.m_transaction.empty()) {
		const auto & all_tx_hash = block.m_header.m_all_tx_hash;
		const auto zero_filled = std::all_of(all_tx_hash.cbegin(), all_tx_hash.cend(), [](unsigned char b){return (b == (0x00));});
		return zero_filled;
	}
	c_merkle_tree merkle_tree;
	for (const auto & transaction : block.m_transaction) {
		merkle_tree.add_hash(transaction.m_txid);
	}
	const auto full_merkle_tree = merkle_tree.get_merkle_tree();
	const auto & merkle_root = full_merkle_tree.at(0);
	return (block.m_header.m_all_tx_hash == merkle_root);
}

bool c_block_verifier::check_txids(const c_block & block) const noexcept {
	for (const auto & transaction : block.m_transaction) {
		const auto txid = c_txid_generate::generate_txid(transaction);
		if (txid != transaction.m_txid) return false;
	}
	return true;
}

bool c_block_verifier::check_signatures(const c_block & block) const {
	const auto miners_public_keys = m_utxo.get_all_miners_public_keys();
	size_t valid_signatures = 0;
	const auto actual_hash = block.m_header.m_actual_hash;
	for (const auto & signature : block.m_header.m_all_signatures) {
		for (const auto & public_key : miners_public_keys) {
			const auto signature_ok = n_bip32::c_key_manager_BIP32::verify(actual_hash.data(), actual_hash.size(), signature, public_key);
			if (signature_ok) {
				valid_signatures++;
				break;
			}
		}
	}
	if (valid_signatures < n_blockchainparams::minimal_valid_signatures_in_block) return false;
	else return true;
}

bool c_block_verifier::check_transactions(const c_block & block) const {
	std::atomic<size_t> index = 0;
	std::vector<std::future<bool>> result_futures;
	for (size_t i = 0; i < m_number_of_threads; i++) {
		std::future<bool> future = std::async(std::launch::async, [&]{
			size_t tx_index = index.fetch_add(1);
			while (tx_index < block.m_transaction.size()) {
				const auto & tx = block.m_transaction.at(tx_index);
				if (!check_transaction(m_blockchain, tx, m_utxo)) return false;
				tx_index = index.fetch_add(1);
			}
			return true;
		});
		result_futures.emplace_back(std::move(future));
	}
	for (auto & future : result_futures) future.wait();
	for (auto & future : result_futures) {
		if (future.get() == false) return false;
	}
	return true;
}

bool c_block_verifier::check_actual_hash(const c_block & block) const {
	const auto block_hash = generate_block_hash(block.m_header);
	return (block.m_header.m_actual_hash == block_hash);
}

bool c_block_verifier::is_genesis(const c_block & block) const {
	if (block.m_header.m_parent_hash == n_blockchainparams::genesis_block_params::m_parent_hash) return true;
	else return false;
}
