#ifndef BLOCK_RECORD_HPP
#define BLOCK_RECORD_HPP

#include "block.hpp"

/**
 * @brief The c_block_record struct
 * leveldb information about single block
 * based on https://en.bitcoin.it/wiki/Bitcoin_Core_0.11_(ch_2):_Data_Storage
 */
struct c_block_record {
	c_header m_header;
	unsigned int m_height;
	unsigned int m_number_of_transactions;
	std::string m_file_contains_block;
	int m_position_in_file;
	unsigned int m_size_of_binary_data;
};

////////////////////////////////////////////////////////////

struct c_file_info_record {
	unsigned int m_number_of_blocks;
	unsigned int m_filesize;
	unsigned int m_height_lowest;
	unsigned int m_height_highest;
};

////////////////////////////////////////////////////////////

struct c_transaction_record {
	std::string m_file_contains_block;
	unsigned int m_offset_of_block; // offset of block contains this transaction
	unsigned int m_offset_of_transaction; // offset of transaction in block
	t_hash_type m_block_id;
};

bool operator==(const c_block_record & lhs, const c_block_record & rhs) noexcept;
#endif // BLOCK_RECORD_HPP
