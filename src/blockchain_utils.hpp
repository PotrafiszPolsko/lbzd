#ifndef BLOCKCHAIN_UTILS_HPP
#define BLOCKCHAIN_UTILS_HPP
#include "block.hpp"
#include "blockchain.hpp"
#include "utxo.hpp"

t_hash_type generate_block_hash(const c_header & header);
bool check_transaction(const c_blockchain & blockchain, const c_transaction & tx, const c_utxo & utxo);
size_t get_minimum_number_of_block_signatures(const size_t number_of_active_miners);

#endif // BLOCKCHAIN_UTILS_HPP
