#include "block_record.hpp"

bool operator==(const c_block_record & lhs, const c_block_record & rhs) noexcept {
	if(lhs.m_header != rhs.m_header) return false;
	if(lhs.m_file_contains_block != rhs.m_file_contains_block) return false;
	if(lhs.m_height != rhs.m_height) return false;
	if(lhs.m_number_of_transactions != rhs.m_number_of_transactions) return false;
	if(lhs.m_position_in_file != rhs.m_position_in_file) return false;
	if(lhs.m_size_of_binary_data != rhs.m_size_of_binary_data) return false;
	return true;
}
