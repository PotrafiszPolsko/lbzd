#include "types.hpp"
#include "transaction.hpp"

struct t_authorization_data {
		t_hash_type m_txid;
		t_transactiontype m_type_of_transaction;
		t_public_key_type m_voting_group;
};
