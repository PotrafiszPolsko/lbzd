#ifndef ADMINSYS_HPP
#define ADMINSYS_HPP

#include "miner.hpp"
#include "wallet.hpp"

class c_adminsys {
	public:
		c_adminsys(const std::filesystem::path & wallet_path);
		c_block mine_genesis_block() const;
		c_block mine_block(const c_block & prev_block, c_mempool & mempool);
		c_transaction generate_miner_auth_tx(const t_public_key_type & miner_pk) const;
		c_transaction generate_organizer_auth_tx(const t_public_key_type & organizer_pk) const;
	private:

		c_wallet m_wallet;
		c_miner_genesis m_genesis_block_miner;
		c_miner m_miner; ///< miner for block except genesis
};

#endif // ADMINSYS_HPP
