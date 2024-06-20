#ifndef MERKLE_TREE_HPP
#define MERKLE_TREE_HPP

#include <array>
#include <set>
#include <sodium.h>
#include <vector>
#include "types.hpp"

/**
 * @brief The c_merkle_tree class
 */
class c_merkle_tree {
	public:
		/**
		 * @brief add_hash add hash to internal set
		 */
		void add_hash(const t_hash_type & hash);
		/**
		 * @brief get_merkle_tree Generate Merkle tree from hashes added by @ref add_hash.
		 * @throws std::logic_error when object is empty
		 * @return merkle tree in binary heap format. Elemant on index 0 i a merkle root
		 */
		std::vector<t_hash_type> get_merkle_tree() const;
		/**
		 * @brief get_branch_merkle_tree Generate merkle branch for given txid. @param txid must be in lower tree level.
		 * @return Vector of hashes.
		 * For generate root from branch you need to hash last element + penultimate element. Next result from this operation
		 * must be hashed with next element. I.e. for branch [A][B][C] for calculate root you need to 
		 * H(H([C]+[B])+[A]) where H is blake2b function.
		 * Hashing pair order id lexicographical so when [A] is less than [B] you always pass [A] before [B].
		 */
		std::vector<t_hash_type> get_branch_merkle_tree(const t_hash_type & txid);
	private:
		std::set<t_hash_type> m_sorted_hashes;
		/**
		 * @return hash generated from 2 concatenated inputs
		 */
};

#endif // MERKLE_TREE_HPP
