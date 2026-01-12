#include "organizer.hpp"
#include "txid_generate.hpp"
#include <random>


t_public_key_type c_organizer::get_pk() const noexcept {
	return m_wallet.get_main_pk();
}

c_transaction c_organizer::add_voting_protocol(const std::vector<unsigned char> & voting_protocol) const {
	c_transaction tx;
	tx.m_type = t_transactiontype::another_voting_protocol;
	{
		c_vin vin;
		vin.m_txid.fill(0x00);
		vin.m_pk = m_wallet.get_main_pk();
		tx.m_vin.push_back(std::move(vin));
	}
	{
		c_vout vout;
		vout.m_pkh.fill(0x00);
		tx.m_vout.push_back(std::move(vout));
	}
	tx.m_allmetadata = voting_protocol;
	tx.m_txid = c_txid_generate::generate_txid(tx);
	tx.m_vin.at(0).m_sign = m_wallet.sign_tx_by_main_identity(tx);
	return tx;
}

c_transaction c_organizer::get_auth_tx_of_organizer(const c_utxo &utxo, const c_blockchain &blockchain) const {
	const auto txid_of_tx_auth_organizer = utxo.get_txid_of_tx_auth_organizer(m_wallet.get_main_pk());
	return blockchain.get_transaction(txid_of_tx_auth_organizer);
}
