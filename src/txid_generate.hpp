#ifndef TXID_GENERATE_HPP
#define TXID_GENERATE_HPP

#include "transaction.hpp"
#include "types.hpp"

class c_txid_generate {
	public:
		static t_hash_type generate_txid(const c_transaction & transaction);
	private:
		static t_hash_type generate_vin_hash(const c_vin & vin);
		static t_hash_type generate_vout_hash(const c_vout & vout);
};

#endif // TXID_GENERATE_HPP
