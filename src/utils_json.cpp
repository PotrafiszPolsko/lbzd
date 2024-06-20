#include "utils_json.hpp"

void to_json(nlohmann::json &result , const c_vout &vout) {
	std::string m_pkh_str;
	m_pkh_str.resize(vout.m_pkh.size()*2+1);
	sodium_bin2hex(m_pkh_str.data(), m_pkh_str.size(), vout.m_pkh.data(), vout.m_pkh.size());
	result["pkh"] = m_pkh_str.c_str();
	result["amount"] = vout.m_amount;
}

void to_json(nlohmann::json &result , const c_vin &vin) {
	std::string m_txid_str;
	m_txid_str.resize(vin.m_txid.size()*2+1);
	sodium_bin2hex(m_txid_str.data(), m_txid_str.size(), vin.m_txid.data(), vin.m_txid.size());
	result["vin_txid"] = m_txid_str.c_str();
	std::string m_sign_str;
	m_sign_str.resize(vin.m_sign.size()*2+1);
	sodium_bin2hex(m_sign_str.data(), m_sign_str.size(), vin.m_sign.data(), vin.m_sign.size());
	result["sign"] = m_sign_str.c_str();
	std::string m_pk_str;
	m_pk_str.resize(vin.m_pk.size()*2+1);
	sodium_bin2hex(m_pk_str.data(), m_pk_str.size(), vin.m_pk.data(), vin.m_pk.size());
	result["pk"] = m_pk_str.c_str();
}

void to_json(nlohmann::json &result , const c_transaction &tx) {
	result["type"] = tx.m_type;
	result["vin"] = tx.m_vin;
	result["vout"] = tx.m_vout;
	std::string m_txid_str;
	m_txid_str.resize(tx.m_txid.size()*2+1);
	sodium_bin2hex(m_txid_str.data(), m_txid_str.size(), tx.m_txid.data(), tx.m_txid.size());
	result["txid"] = m_txid_str.c_str();
	std::string m_allmetadata_str;
	m_allmetadata_str.resize(tx.m_allmetadata.size()*2+1);
	sodium_bin2hex(m_allmetadata_str.data(), m_allmetadata_str.size(), tx.m_allmetadata.data(), tx.m_allmetadata.size());
	result["allmetadata"] = m_allmetadata_str.c_str();
}

void to_json(nlohmann::json &result, const t_signature_type &signature ) {
	std::string signature_str;
	signature_str.resize(signature.size()*2+1);
	sodium_bin2hex(signature_str.data(), signature_str.size(), signature.data(), signature.size());
	result = signature_str.c_str();
}

void to_json(nlohmann::json &result , const c_header &header) {
	result["version"] = header.m_version;
	std::string m_parent_hash_str;
	m_parent_hash_str.resize(header.m_parent_hash.size()*2+1);
	sodium_bin2hex(m_parent_hash_str.data(), m_parent_hash_str.size(), header.m_parent_hash.data(), header.m_parent_hash.size());
	result["parent_hash"] = m_parent_hash_str.c_str();
	std::string m_actual_hash_str;
	m_actual_hash_str.resize(header.m_actual_hash.size()*2+1);
	sodium_bin2hex(m_actual_hash_str.data(), m_actual_hash_str.size(), header.m_actual_hash.data(), header.m_actual_hash.size());
	result["actual_hash"] = m_actual_hash_str.c_str();
	result["block_time"] = header.m_block_time;
	std::string m_all_tx_hash_str;
	m_all_tx_hash_str.resize(header.m_all_tx_hash.size()*2+1);
	sodium_bin2hex(m_all_tx_hash_str.data(), m_all_tx_hash_str.size(), header.m_all_tx_hash.data(), header.m_all_tx_hash.size());
	result["all_tx_hash"] = m_all_tx_hash_str.c_str();
	nlohmann::json all_signatures_str;
	for(const auto & signature:header.m_all_signatures) {
		std::string signature_str;
		signature_str.resize(signature.size()*2+1);
		sodium_bin2hex(signature_str.data(), signature_str.size(), signature.data(), signature.size());
		signature_str.pop_back();
		all_signatures_str.push_back(signature_str);
	}
	result["all_signatures"] = all_signatures_str;
}

void to_json(nlohmann::json &result , const c_block &block) {
	result["transactions"] = block.m_transaction;
	result["header"] = block.m_header;
}

void from_json(const nlohmann::json &input, c_vin &vin) {
	int ret = 0;
	std::string vin_txid_as_str;
	input.at("vin_txid").get_to(vin_txid_as_str);
	ret = sodium_hex2bin(vin.m_txid.data(), vin.m_txid.size(), vin_txid_as_str.data(), vin_txid_as_str.size(), nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::string sign_as_str;
	input.at("sign").get_to(sign_as_str);
	ret = sodium_hex2bin(vin.m_sign.data(), vin.m_sign.size(), sign_as_str.data(), sign_as_str.size(), nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::string pk_as_str;
	input.at("pk").get_to(pk_as_str);
	ret = sodium_hex2bin(vin.m_pk.data(), vin.m_pk.size(), pk_as_str.data(), pk_as_str.size(), nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
}

void from_json(const nlohmann::json &input, c_vout &vout) {
	std::string pkh_as_str;
	input.at("pkh").get_to(pkh_as_str);
	const auto ret = sodium_hex2bin(vout.m_pkh.data(), vout.m_pkh.size(), pkh_as_str.data(), pkh_as_str.size(), nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	input.at("amount").get_to(vout.m_amount);
}

void from_json(const nlohmann::json &input, c_transaction &tx) {
	input.at("type").get_to(tx.m_type);
	int ret = 0;
	input.at("vin").get_to(tx.m_vin);
	input.at("vout").get_to(tx.m_vout);
	std::string txid_as_str;
	input.at("txid").get_to(txid_as_str);
	ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(), txid_as_str.data(), txid_as_str.size(), nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::string allmetadata_as_str;
	input.at("allmetadata").get_to(allmetadata_as_str);
	tx.m_allmetadata.resize(allmetadata_as_str.size()/2);
	ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(), allmetadata_as_str.data(), allmetadata_as_str.size(), nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
}
