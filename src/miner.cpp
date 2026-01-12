#include "miner.hpp"
#include "params.hpp"
#include "utils.hpp"
#include "blockchain_utils.hpp"
#include "merkle_tree.hpp"
#include <algorithm>
#include <iostream>
#include <chrono>
#include <thread>
#include <cassert>
#include <random>

size_t c_miner::calculate_header_size(size_t number_of_active_miners, size_t metadata_size) const {
	const size_t minimal_number_of_miner_signatures = get_minimum_number_of_block_signatures(number_of_active_miners);
	const size_t size_of_signatures = minimal_number_of_miner_signatures * sizeof(t_signature_type);
	return 
			sizeof(c_header::m_version)
			+ sizeof(c_header::m_parent_hash)
			+ sizeof(c_header::m_actual_hash)
			+ sizeof(c_header::m_block_time)
			+ sizeof(c_header::m_all_tx_hash)
			+ metadata_size
	        + size_of_signatures;
}

c_block c_miner::mine_block(const c_block & prev_block, size_t number_of_active_miners, c_mempool & mempool) {
	c_block actual_block;
	actual_block.m_header.m_block_time = prev_block.m_header.m_block_time + n_blockchainparams::blocks_diff_time_in_sec;
	const auto header_size = calculate_header_size(number_of_active_miners, 0);
	size_t block_size = header_size;
	actual_block.m_header.m_version = 0;
	while (!mempool.empty()) {
		const auto transaction_size = size_of_transaction(mempool.get_first_transaction());
		if ((block_size + transaction_size) > n_blockchainparams::max_block_size) break;
		auto tx = mempool.get_and_remove_transaction();
		bool the_same_metadata_or_pkh = false;
		if(!actual_block.m_transaction.empty() && tx.m_type == t_transactiontype::another_voting_protocol) {
			for(const auto &tx_from_actual_block : actual_block.m_transaction) {
				if(tx_from_actual_block.m_allmetadata==tx.m_allmetadata) {
					the_same_metadata_or_pkh = true;
					break;
				}
			}
		} else if(!actual_block.m_transaction.empty() && (tx.m_type == t_transactiontype::authorize_miner || tx.m_type == t_transactiontype::authorize_organizer)) {
			for(const auto &tx_from_actual_block : actual_block.m_transaction) {
				if(tx_from_actual_block.m_vout.at(0).m_pkh==tx.m_vout.at(0).m_pkh) {
					the_same_metadata_or_pkh = true;
					break;
				}
			}
		}
		if(the_same_metadata_or_pkh==true) continue;
		actual_block.m_transaction.emplace_back(std::move(tx));
		block_size += transaction_size;
	}
	std::copy(std::begin(prev_block.m_header.m_actual_hash), std::end(prev_block.m_header.m_actual_hash), std::begin(actual_block.m_header.m_parent_hash));
	c_merkle_tree merkle_tree_generator;
	for (const auto & transaction : actual_block.m_transaction) {
		merkle_tree_generator.add_hash(transaction.m_txid);
	}
	try {
		const auto merkle_tree = merkle_tree_generator.get_merkle_tree();
		actual_block.m_header.m_all_tx_hash = merkle_tree.at(0);
	} catch (const std::logic_error &) {
		actual_block.m_header.m_all_tx_hash.fill(0x00); // no tx in block
	}
	actual_block.m_header.m_actual_hash = generate_block_hash(actual_block.m_header);
	return actual_block;
}

c_block c_miner_genesis::mine_block() const {
	c_block genesis_block;
	genesis_block.m_header.m_version = n_blockchainparams::genesis_block_params::m_version;
	genesis_block.m_header.m_block_time = get_unix_time();
	genesis_block.m_header.m_all_tx_hash = n_blockchainparams::genesis_block_params::m_all_tx_hash;
	genesis_block.m_header.m_parent_hash = n_blockchainparams::genesis_block_params::m_parent_hash;
	genesis_block.m_header.m_actual_hash = generate_block_hash(genesis_block.m_header);
	return genesis_block;
}

