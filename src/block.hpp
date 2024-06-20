#ifndef BLOCK_HPP
#define BLOCK_HPP
#include <cstdint>
#include <vector>
#include "transaction.hpp"
#include "types.hpp"

struct c_header {
	uint8_t m_version = 0;
	t_hash_type m_parent_hash;
	t_hash_type m_actual_hash;
	uint32_t m_block_time;
	t_hash_type m_all_tx_hash; // merkle root
	std::vector<t_signature_type> m_all_signatures;
};

struct c_block {
	c_header m_header;
	std::vector<c_transaction> m_transaction; // max size (2^32) - 1
};

size_t size_of_header(const c_header &header); //size of header of block in bytes
size_t size_of_vin(const c_vin &vin); //size of vin of tx in bytes
size_t size_of_vout(const c_vout &vout); //size of vout of tx in bytes
size_t size_of_transaction(const c_transaction &txs); //size of transactions of block in bytes
size_t size_of_block(const c_block &block); //size of block in bytes

bool operator==(const c_header &lhs, const c_header &rhs) noexcept;
bool operator!=(const c_header &lhs, const c_header &rhs) noexcept;

bool operator==(const c_block &lhs, const c_block &rhs) noexcept;
bool operator!=(const c_block &lhs, const c_block &rhs) noexcept;

#endif // BLOCK_HPP
