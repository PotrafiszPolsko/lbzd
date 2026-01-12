#ifndef MINER_HPP
#define MINER_HPP
#include "mempool.hpp"
#include "blockchain.hpp"
#include "utxo.hpp"
#include "types.hpp"
#include "key_manager_bip32.hpp"

class c_miner {
	private:
		size_t calculate_header_size(size_t number_of_active_miners, size_t metadata_size) const;
	public:
		virtual ~c_miner() = default;
		c_block mine_block(const c_block & prev_block, size_t number_of_active_miners, c_mempool & mempool);
};

class c_miner_genesis : private c_miner {
	public:
		c_block mine_block() const;
};

#endif // MINER_HP
