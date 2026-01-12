#include "blockchain_utils.hpp"
#include "params.hpp"
#include "utils.hpp"
#include "key_manager_bip32.hpp"

t_hash_type generate_block_hash(const c_header & header) {
	std::vector<unsigned char> header_as_bytes;
	const auto version_as_byte = get_array_byte(header.m_version);
	std::copy(version_as_byte.begin(), version_as_byte.end(), std::back_inserter(header_as_bytes));
	std::copy(header.m_parent_hash.begin(), header.m_parent_hash.end(), std::back_inserter(header_as_bytes));
	const auto block_time_as_bytes = get_array_byte(header.m_block_time);
	std::copy(block_time_as_bytes.begin(), block_time_as_bytes.end(), std::back_inserter(header_as_bytes));
	std::copy(header.m_all_tx_hash.begin(), header.m_all_tx_hash.end(), std::back_inserter(header_as_bytes));
	const auto block_actual_hash = generate_hash(header_as_bytes);
	return block_actual_hash;
}

bool check_transaction(const c_transaction &tx, const c_utxo & utxo) {
	if (tx.m_type == t_transactiontype::generate) {
		if (tx.m_vin.size() != 0) return false;
	} else if (tx.m_type == t_transactiontype::authorize_miner) {
		if (tx.m_vin.size() != 1) return false;
		const auto pk = tx.m_vin.at(0).m_pk;
		// only adminsys can authorize
		if(!n_blockchainparams::is_pk_adminsys(pk)) return false;
	}else if (tx.m_type == t_transactiontype::authorize_organizer) {
		if (tx.m_vin.size() != 1) return false;
		const auto pk = tx.m_vin.at(0).m_pk;
		if ((!n_blockchainparams::is_pk_adminsys(pk)) && (!utxo.is_pk_organizer(pk))) return false;
	} else if (tx.m_type == t_transactiontype::another_voting_protocol) {
		const auto organizer_pk = tx.m_vin.at(0).m_pk;
		if (!utxo.is_pk_organizer(organizer_pk)) return false;
	} else {
		return false;
	}
	const auto txid = tx.m_txid;
	// check transactions signatures
	for (const auto & vin : tx.m_vin) {
		if (!n_bip32::c_key_manager_BIP32::verify(txid.data(), txid.size(), vin.m_sign, vin.m_pk)) return false;
	}
	return true;
}

size_t get_minimum_number_of_block_signatures(const size_t number_of_active_miners) {
	auto minimal_number_of_miner_signatures = std::ceil(number_of_active_miners*(n_blockchainparams::percent_of_miners_needed_to_sign_block/100.));
	return static_cast<size_t>(minimal_number_of_miner_signatures);
}
