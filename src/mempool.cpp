#include "mempool.hpp"

void c_mempool::remove_transaction_if_exists(const t_hash_type & txid) {
	m_transactions.erase(txid);
}

const c_transaction & c_mempool::get_first_transaction() const {
	return m_transactions.cbegin()->second;
}

c_transaction c_mempool::get_and_remove_transaction() {
	const auto it = m_transactions.cbegin();
	c_transaction tx = std::move(it->second);
	m_transactions.erase(it);
	return tx;
}

size_t c_mempool::size() const noexcept {
	return m_transactions.size();
}

bool c_mempool::empty() const noexcept {
	return m_transactions.empty();
}

bool c_mempool::is_transaction_in_mempool(const t_hash_type & txid) const {
	if (m_transactions.count(txid) == 1) return true;
	else return false;
}

std::vector<c_transaction> c_mempool::get_transactions() const {
	std::vector<c_transaction> transactions;
	transactions.reserve(m_transactions.size());
	std::transform(
				m_transactions.cbegin(),
				m_transactions.cend(),
				std::back_inserter(transactions),
				[](const auto & pair){return pair.second;});
	return transactions;
}
