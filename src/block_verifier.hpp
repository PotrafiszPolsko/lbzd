#ifndef BLOCK_VERIFIER_HPP
#define BLOCK_VERIFIER_HPP

#include "blockchain.hpp"
#include "utxo.hpp"

class c_block_verifier {
	public:
		c_block_verifier(const c_blockchain & blockchain, const c_utxo & utxo, const size_t number_threads);
		bool verify_block(const c_block & block) const;
	private:
		const c_blockchain & m_blockchain;
		const c_utxo & m_utxo;
		const size_t m_number_of_threads;
		bool check_parent_hash(const c_block & block) const;
		bool check_time_diff(const c_block & block) const;
		bool check_transaction_merkle_root(const c_block & block) const;
		bool check_txids(const c_block & block) const noexcept;
		bool check_signatures(const c_block & block) const;
		bool check_transactions(const c_block & block) const;
		bool check_actual_hash(const c_block & block) const;
		bool is_genesis(const c_block & block) const;
};

#endif // BLOCK_VERIFIER_HPP
