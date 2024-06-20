#ifndef AUTHORIZATION_LEVEL_DATA_HPP
#define AUTHORIZATION_LEVEL_DATA_HPP

#include "types.hpp"

struct t_authorization_level_data {
		t_public_key_type m_pk;
		t_authorization_level m_al;
};

bool operator==(const t_authorization_level_data &lhs, const t_authorization_level_data &rhs);

#endif // AUTHORIZATION_LEVEL_DATA_HPP
