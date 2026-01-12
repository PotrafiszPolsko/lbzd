#ifndef ORGANIZER_HPP
#define ORGANIZER_HPP

#include "wallet.hpp"
#include "utxo.hpp"
#include "blockchain.hpp"


class c_organizer {
	public:
		t_public_key_type get_pk() const noexcept;
		c_transaction add_voting_protocol(const std::vector<unsigned char> & hash_voting_protocol) const;
		c_transaction get_auth_tx_of_organizer(const c_utxo & utxo, const c_blockchain & blockchain) const;
	private:
		c_wallet m_wallet;
};

#endif // ORGANIZER_HPP
