#include "types.hpp"

bool operator==(const t_voting_metadata & lhs, const t_voting_metadata & rhs) noexcept {
	if(lhs.m_authorization_level != rhs.m_authorization_level) return false;
	if(lhs.m_name != rhs.m_name) return false;
	if(lhs.m_number_of_blocks_to_the_end != rhs.m_number_of_blocks_to_the_end) return false;
	if(lhs.m_number_of_choice != rhs.m_number_of_choice) return false;
	if(lhs.m_options != rhs.m_options) return false;
	if(lhs.m_question != rhs.m_question) return false;
	if(lhs.m_start_timepoint != rhs.m_start_timepoint) return false;
	if(lhs.m_voting_type != rhs.m_voting_type) return false;
	return true;
}
