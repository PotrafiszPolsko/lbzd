#include "blockchain_utils.hpp"
#include "params.hpp"
#include "utils.hpp"
#include "key_manager_bip32.hpp"
#include "blockchain_module.hpp"
#include "logger.hpp"

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

bool check_transaction(const c_blockchain &blockchain, const c_transaction &tx, const c_utxo & utxo) {
	std::string txid_str;
	txid_str.resize(tx.m_txid.size()*2+1);
	sodium_bin2hex(txid_str.data(), txid_str.size(), tx.m_txid.data(), tx.m_txid.size());
	LOG(debug) << "Check transaction " << txid_str;
	if (tx.m_type == t_transactiontype::generate) {
		if (tx.m_vin.size() != 0) {
			LOG(warning) << "Bad vin size";
			return false;
		}
	} else if ((tx.m_type == t_transactiontype::add_open_vote) || (tx.m_type == t_transactiontype::add_secret_vote)) {
		if (tx.m_vin.size() == 0)
			return false;
		if (tx.m_vout.size() == 0) {
			LOG(warning) << "Bad vout size";
			return false;
		}
		// check vout pass to any of vout option
		const auto metadata = get_metadata_map(tx.m_allmetadata);
		const auto vi_as_vector = metadata.find("VI")->second;
		t_hash_type vi;
		std::copy(vi_as_vector.cbegin(), vi_as_vector.cend(), vi.begin());
		if (tx.m_type == t_transactiontype::add_open_vote) {
			if (utxo.check_the_voter_voted(tx.m_vin.front().m_pk, vi)) {
				LOG(warning) << "Voter voted in this voting";
				return false;
			}
		}
		const auto create_voting_tx = blockchain.get_transaction(vi);
		const auto create_voting_metadata_map = get_metadata_map(create_voting_tx.m_allmetadata);
		auto iterators_OP = create_voting_metadata_map.equal_range("OP");
		std::vector<t_hash_type> option_addresses;
		for (auto iterator = iterators_OP.first; iterator != iterators_OP.second; ++iterator) {
			const auto &option = iterator->second;
			const auto option_address = c_blockchain_module::get_vote_option_hash(create_voting_tx, option);
			option_addresses.push_back(option_address);
		}
		const auto vote_address = tx.m_vout.at(0).m_pkh;
		const auto count = std::count(option_addresses.cbegin(), option_addresses.cend(), vote_address);
		if (count == 0) {
			LOG(warning) << "Bad option address";
			return false;
		}
	} else if (tx.m_type == t_transactiontype::authorize_miner) {
		if (tx.m_vin.size() != 1) {
			LOG(warning) << "Bad vin size";
			return false;
		}
		const auto pk = tx.m_vin.at(0).m_pk;
		// only adminsys can authorize
		if(!n_blockchainparams::is_pk_adminsys(pk)) {
			LOG(warning) << "Not adminsys pk";
			return false;
		}
	} else if (tx.m_type == t_transactiontype::authorize_organizer) {
		if (tx.m_vin.size() != 1) {
			LOG(warning) << "Bad vin size";
			return false;
		}
		const auto pk = tx.m_vin.at(0).m_pk;
		if ((!n_blockchainparams::is_pk_adminsys(pk)) && (!utxo.is_pk_organizer(pk))) {
			LOG(warning) << "Not adminsys or organizer pk";
			return false;
		}
	} else if (tx.m_type == t_transactiontype::authorize_issuer) {
		const auto pk = tx.m_vin.at(0).m_pk;
		if ((!n_blockchainparams::is_pk_adminsys(pk)) && (!utxo.is_pk_organizer(pk))) {
			LOG(warning) << "Not adminsys or organizer pk";
			return false;
		}
	} else if (tx.m_type == t_transactiontype::authorize_voter) {
		const auto pk = tx.m_vin.at(0).m_pk;
		if ((!n_blockchainparams::is_pk_adminsys(pk)) && (!utxo.is_pk_issuer(pk)) && (!utxo.is_pk_organizer(pk))) {
			LOG(warning) << "Not adminsys, organizer or issuer pk";
			return false;
		}
	} else if (tx.m_type == t_transactiontype::create_voting) {
		const auto organizer_pk = tx.m_vin.at(0).m_pk;
		if (!utxo.is_pk_organizer(organizer_pk)) {
			LOG(warning) << "Not organizer pk";
			return false;
		}
	} else if (tx.m_type == t_transactiontype::coin_join) {
		if (tx.m_vin.size() != tx.m_vout.size()) {
			LOG(warning) << "Bad vin or vout size";
			return false;
		}
		const auto metadata_map = get_metadata_map(tx.m_allmetadata);
		if (metadata_map.count("VI") != 1) {
			LOG(warning) << "No VI metadata field";
			return false;
		}
		for (const auto & vin : tx.m_vin) {
			if (utxo.is_pk_issuer(vin.m_pk)) {
				const auto voting_id_vector = metadata_map.find("VI")->second;
				const auto voting_id = container_to_array_of_uchars<hash_size>(voting_id_vector);
				if (utxo.check_the_voter_voted(vin.m_pk, voting_id)) {
					LOG(warning) << "Voter voted in this voting";
					return false;
				}
			}
			if (utxo.get_amount_on_pk(vin.m_pk) == 0) {
				LOG(warning) << "No voting right on this pk";
				return false;
			}
		}
	} else if (tx.m_type == t_transactiontype::another_voting_protocol) {
		const auto organizer_pk = tx.m_vin.at(0).m_pk;
		if (!utxo.is_pk_organizer(organizer_pk)) {
			LOG(warning) << "Not organizer pk";
			return false;
		}
	} else if (tx.m_type == t_transactiontype::hash_personal_data) {
		const auto issuer_pk = tx.m_vin.at(0).m_pk;
		if (!utxo.is_pk_issuer(issuer_pk)) {
			LOG(warning) << "Not issuer pk";
			return false;
		}
	} else {
		LOG(warning) << "Bad transaction type";
		return false;
	}
	const auto txid = tx.m_txid;
	// check transactions signatures
	for (const auto & vin : tx.m_vin) {
		if (!n_bip32::c_key_manager_BIP32::verify(txid.data(), txid.size(), vin.m_sign, vin.m_pk)) {
			LOG(warning) << "Bad signature";
			return false;
		}
	}
	if (tx.m_type == t_transactiontype::add_secret_vote) {
	// check vouts for every vin
		for (const auto & vin : tx.m_vin) {
			const auto transaction = blockchain.get_transaction(vin.m_txid);
			const auto pkh = generate_hash(vin.m_pk);
			if(std::none_of(transaction.m_vout.cbegin(), transaction.m_vout.cend(), [&pkh](c_vout vout){return vout.m_pkh==pkh;})) {
				LOG(warning) << "Bad vin txid";
				return false;
			}
		}
	}
	return true;
}

size_t get_minimum_number_of_block_signatures(const size_t number_of_active_miners) {
	auto minimal_number_of_miner_signatures = std::ceil(number_of_active_miners*(n_blockchainparams::percent_of_miners_needed_to_sign_block/100.));
	return static_cast<size_t>(minimal_number_of_miner_signatures);
}
