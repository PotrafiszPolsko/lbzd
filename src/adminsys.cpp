#include "adminsys.hpp"
#include "params.hpp"
#include "txid_generate.hpp"
#include "utils.hpp"
#include <cassert>

c_adminsys::c_adminsys(const std::filesystem::path & wallet_path)
	:
#if defined (IVOTING_TESTS) || defined (COVERAGE_TESTS)
	  m_wallet(n_blockchainparams::entropy_seed, wallet_path),
	  m_genesis_block_miner(),
	  m_miner()
#else
      m_wallet(wallet_path),
	  m_genesis_block_miner(),
	  m_miner()
#endif
{	
	const auto main_pkh = m_wallet.get_main_pkh();
	assert(std::any_of(n_blockchainparams::admins_sys_pub_keys.cbegin(), n_blockchainparams::admins_sys_pub_keys.cend(), [&main_pkh](const t_public_key_type & pk)
	{
		const auto pk_hash = generate_hash(pk);
		return main_pkh==pk_hash;
	}));
}

c_block c_adminsys::mine_genesis_block() const {
	return m_genesis_block_miner.mine_block();
}

c_block c_adminsys::mine_block(const c_block & prev_block, c_mempool & mempool) {
	return m_miner.mine_block(prev_block, 0, mempool);
}

c_transaction c_adminsys::generate_miner_auth_tx(const t_public_key_type & authorized_miner_pk) const {
	c_transaction tx;
	tx.m_type = t_transactiontype::authorize_miner;
	{
		c_vout vout;
		vout.m_pkh = generate_hash(authorized_miner_pk);
		tx.m_vout.push_back(std::move(vout));
	}
	{
		c_vin vin;
		vin.m_txid.fill(0x00);
		vin.m_pk = m_wallet.get_main_pk();
		vin.m_sign.fill(0x00);
		tx.m_vin.push_back(std::move(vin));
	}
	std::copy(authorized_miner_pk.cbegin(), authorized_miner_pk.cend(), std::back_inserter(tx.m_allmetadata));
	tx.m_txid = c_txid_generate::generate_txid(tx);
	return m_wallet.get_sign_tx(tx);
}

c_transaction c_adminsys::generate_organizer_auth_tx(const t_public_key_type & authorized_organizer_pk) const {
	c_transaction tx;
	tx.m_type = t_transactiontype::authorize_organizer;
	{
		c_vout vout;
		vout.m_pkh = generate_hash(authorized_organizer_pk);
		tx.m_vout.push_back(std::move(vout));
	}
	{
		c_vin vin;
		vin.m_txid.fill(0x00);
		vin.m_pk = m_wallet.get_main_pk();
		vin.m_sign.fill(0x00);
		tx.m_vin.push_back(std::move(vin));
	}
	tx.m_allmetadata.clear();
	tx.m_txid = c_txid_generate::generate_txid(tx);
	return m_wallet.get_sign_tx(tx);
}
