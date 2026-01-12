#include "txid_generate.hpp"
#include <array>
#include <set>
#include "utils.hpp"

t_hash_type c_txid_generate::generate_txid(const c_transaction & transaction) {
	std::set<t_hash_type> vin_hashes;
	for (const auto & vin : transaction.m_vin) {
		vin_hashes.emplace(generate_vin_hash(vin));
	}
	std::set<t_hash_type> vout_hashes;
	for (const auto & vout : transaction.m_vout) {
		vin_hashes.emplace(generate_vout_hash(vout));
	}
	
	std::vector<unsigned char> input_data;
	input_data.push_back(static_cast<unsigned char>(transaction.m_type));
	for (const auto & hash : vin_hashes) {
		std::copy(hash.begin(), hash.end(), std::back_inserter(input_data));
	}
	for (const auto & hash : vout_hashes) {
		std::copy(hash.begin(), hash.end(), std::back_inserter(input_data));
	}
	std::copy(transaction.m_allmetadata.cbegin(), transaction.m_allmetadata.cend(), std::back_inserter(input_data));
	const auto txid = generate_hash(input_data);
	return txid;
}

t_hash_type c_txid_generate::generate_vin_hash(const c_vin & vin) {
	const size_t input_size = vin.m_txid.size() + vin.m_pk.size();
	std::vector<unsigned char> input_data;
	input_data.reserve(input_size);
	std::copy(vin.m_txid.begin(), vin.m_txid.end(), std::back_inserter(input_data));
	std::copy(vin.m_pk.begin(), vin.m_pk.end(), std::back_inserter(input_data));
	return generate_hash(input_data);
}

t_hash_type c_txid_generate::generate_vout_hash(const c_vout & vout) {
	std::vector<unsigned char> input_data;
	std::copy(vout.m_pkh.begin(), vout.m_pkh.end(), std::back_inserter(input_data));
	return generate_hash(input_data);
}
