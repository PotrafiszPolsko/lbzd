#include "params.hpp"
#include <algorithm>

bool n_blockchainparams::is_pk_adminsys(const t_public_key_type &pk) {
		if(std::any_of(n_blockchainparams::admins_sys_pub_keys.cbegin(), n_blockchainparams::admins_sys_pub_keys.cend(), [pk](t_public_key_type admin_pk)
			{return admin_pk==pk;})) return true;
		else return false;
}
