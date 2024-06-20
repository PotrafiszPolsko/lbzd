#include "transaction.hpp"
#include "utils.hpp"
#include <sodium.h>
#include <limits>
#include <cstddef>

bool operator==(const c_transaction &lhs, const c_transaction &rhs) noexcept {
	if (lhs.m_type!=rhs.m_type) return false;
	if (lhs.m_txid!=rhs.m_txid) return false;
	if (lhs.m_allmetadata!=rhs.m_allmetadata) return false;
	if (lhs.m_vin.size()!=rhs.m_vin.size()) return false;
	if (lhs.m_vout.size()!=rhs.m_vout.size()) return false;
	for (const auto & vin : lhs.m_vin) {
		const auto it = std::find(rhs.m_vin.cbegin(), rhs.m_vin.cend(), vin);
		if (it == rhs.m_vin.cend()) return false;
	}
	for (const auto & vout : lhs.m_vout) {
		const auto it = std::find(rhs.m_vout.cbegin(), rhs.m_vout.cend(), vout);
		if (it == rhs.m_vout.cend()) return false;
	}
	return true;
}

bool operator!=(const c_transaction &lhs, const c_transaction &rhs) noexcept {
	return !(lhs == rhs);
}

bool operator<(const c_vout &lhs, const c_vout &rhs) noexcept {
	if (lhs.m_pkh != rhs.m_pkh) return (lhs.m_pkh < rhs.m_pkh);
	if (lhs.m_amount != rhs.m_amount) return (lhs.m_amount < rhs.m_amount);
	return false;
}

bool operator==(const c_vout &lhs, const c_vout &rhs) noexcept {
	if (lhs.m_pkh != rhs.m_pkh) return false;
	if (lhs.m_amount != rhs.m_amount) return false;
	return true;
}

bool operator<(const c_vin &lhs, const c_vin &rhs) noexcept {
	if (lhs.m_pk != rhs.m_pk) return (lhs.m_pk < rhs.m_pk);
	if (lhs.m_txid != rhs.m_txid) return (lhs.m_txid < rhs.m_txid);
	return false;
}

bool operator==(const c_vin &lhs, const c_vin &rhs) noexcept {
	if (lhs.m_pk != rhs.m_pk) return false;
	if (lhs.m_sign != rhs.m_sign) return false;
	if (lhs.m_txid != rhs.m_txid) return false;
	return true;
}

bool operator!=(const c_vin &lhs, const c_vin &rhs) noexcept {
	return !(lhs == rhs);
}

std::unordered_multimap<std::string, std::vector<unsigned char>> get_metadata_map(const std::vector<unsigned char> & allmetadata) {
	std::unordered_multimap<std::string, std::vector<unsigned char>> property_map;
	auto it = allmetadata.cbegin();
	while (it != allmetadata.cend()) {
		std::string key;
		const size_t size_of_key = 2;
		std::copy(it, it + size_of_key, std::back_inserter(key));
		it += size_of_key;
		std::vector<unsigned char> value;
		unsigned int value_size = 0;
		if (key == "VN" || key == "OP" || key == "QS") {
			value_size = std::to_integer<uint8_t>(static_cast<std::byte>(*it));
			it++;
		} else if (key == "CO" || key == "CP" || key == "PK") {
			value_size = public_key_size;
		} else if (key == "NC") {
			value_size = sizeof (uint16_t);
		} else if (key == "AL" || key == "BE" || key == "ST") {
			value_size = sizeof (uint32_t);
		} else if (key == "VI" || key == "PD") {
			value_size = hash_size;
		} else if (key == "VT") {
			value_size = sizeof (uint8_t);
		} else if (key == "NO") {
			value_size = 4;
		} else throw std::invalid_argument("not known key " + key);
		std::copy_n(it, value_size, std::back_inserter(value));
		it += value_size;
		property_map.emplace(std::move(key), std::move(value));
	}
	return property_map;
}

std::vector<unsigned char> get_metadata_variable_length_field(const std::string & key, const std::string & value) {
	if (key.size() != 2) throw std::invalid_argument("Bad key size");
	if (value.size() > std::numeric_limits<uint8_t>::max()) throw std::invalid_argument("voting name is too long");
	std::vector<unsigned char> metadata;
	std::copy(key.cbegin(), key.cend(), std::back_inserter(metadata));
	const auto size = static_cast<unsigned char>(value.size());
	metadata.push_back(size);
	std::copy(value.cbegin(), value.cend(), std::back_inserter(metadata));
	return metadata;
}
