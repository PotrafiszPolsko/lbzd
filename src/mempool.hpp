#ifndef MEMPOOL_HPP
#define MEMPOOL_HPP

#include "transaction.hpp"
#include "blockchain_utils.hpp"
#include <unordered_map>

class c_mempool {
	public:
		c_mempool() = default; //for only tests
		virtual ~c_mempool() = default;
		/**
		 * @brief add_transaction
		 * check transaction and add to internal buffer if valid. Else ignore.
		 */
		template <class T>
		bool add_transaction(T && transaction, const c_utxo & utxo);
		void remove_transaction_if_exists(const t_hash_type & txid);
		const c_transaction & get_first_transaction() const;
		c_transaction get_and_remove_transaction();
		size_t size() const noexcept;
		bool empty() const noexcept;
		bool is_transaction_in_mempool(const t_hash_type & txid) const;
		std::vector<c_transaction> get_transactions() const;
	private:
		/**
		 * @brief m_transactions
		 * full transactions awaiting miners
		 */
		std::unordered_map<t_hash_type, c_transaction> m_transactions; // txid => transaction
};

template <class T>
bool c_mempool::add_transaction(T && transaction, const c_utxo & utxo) {
	// check specify for mempool
	const auto txid = transaction.m_txid;
	if (check_transaction(transaction, utxo)) {
		m_transactions.emplace(txid, std::forward<T>(transaction));
		return true;
	} else {
		return false;
	}
}


#endif // MEMPOOL_HPP
