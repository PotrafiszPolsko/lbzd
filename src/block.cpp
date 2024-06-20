#include"block.hpp"

size_t size_of_header(const c_header &header) { //size of header of block in bytes
	size_t size = 0;
	size = sizeof(header.m_version);
	size += header.m_parent_hash.size();
	size += header.m_actual_hash.size();
	size += sizeof(header.m_block_time);
	size += header.m_all_tx_hash.size();
	for(const auto &sign:header.m_all_signatures) size += sign.size();
	return size;
}

size_t size_of_vin(const c_vin &vin){
	size_t size_of_vin = 0;
	size_of_vin = vin.m_txid.size();
	size_of_vin += vin.m_sign.size();
	size_of_vin += vin.m_pk.size();
	return size_of_vin;
}

size_t size_of_vout(const c_vout &vout){
	size_t size_of_vout = 0;
	size_of_vout = vout.m_pkh.size();
	size_of_vout += sizeof(vout.m_amount);
	return size_of_vout;
}

size_t size_of_transaction(const c_transaction &tx) { //size of transactions of block in bytes
	size_t size = 0;
	size = sizeof(tx.m_type);
	for(const auto &vin:tx.m_vin) size += size_of_vin(vin);
	for(const auto &vout:tx.m_vout) size += size_of_vout(vout);
	size += tx.m_txid.size();
	size += tx.m_allmetadata.size();
	return size;
}

size_t size_of_block(const c_block &block) { //size of block in bytes
	size_t size = 0;
	size = size_of_header(block.m_header);
	for(const auto &tx:block.m_transaction) size += size_of_transaction(tx);
	return size;
}

bool operator==(const c_header &lhs, const c_header &rhs) noexcept {
	if (lhs.m_actual_hash != rhs.m_actual_hash) return false;
	if (lhs.m_all_signatures != rhs.m_all_signatures) return false;
	if (lhs.m_all_tx_hash != rhs.m_all_tx_hash) return false;
	if (lhs.m_block_time != rhs.m_block_time) return false;
	if (lhs.m_parent_hash != rhs.m_parent_hash) return false;
	if (lhs.m_version != rhs.m_version) return false;
	return true;
}

bool operator!=(const c_header &lhs, const c_header &rhs) noexcept {
	return !(lhs == rhs);
}

bool operator==(const c_block &lhs, const c_block &rhs) noexcept {
	if (lhs.m_header != rhs.m_header) return false;
	if (lhs.m_transaction != rhs.m_transaction) return false;
	return true;
}

bool operator!=(const c_block &lhs, const c_block &rhs) noexcept {
	return !(lhs == rhs);
}
