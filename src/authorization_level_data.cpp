#include "authorization_level_data.hpp"

bool operator==(const t_authorization_level_data &lhs, const t_authorization_level_data &rhs) {
	if(lhs.m_pk != rhs.m_pk) return false;
	if(lhs.m_al != rhs.m_al) return false;
	return true;
}
