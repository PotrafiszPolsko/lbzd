#include "merkle_tree.hpp"
#include "utils.hpp"
#include <stdexcept>
#include <cmath>
#include <algorithm>

void c_merkle_tree::add_hash(const t_hash_type & hash) {
	m_sorted_hashes.emplace(hash);
}

std::vector<t_hash_type> c_merkle_tree::get_merkle_tree() const {
	if(m_sorted_hashes.empty()) throw std::logic_error("No hashes added");

	std::vector<t_hash_type> sorted_hashes;
	std::copy(m_sorted_hashes.cbegin(), m_sorted_hashes.cend(), std::back_inserter(sorted_hashes));
	std::vector<t_hash_type> tree;
	if(sorted_hashes.size()==1) return sorted_hashes;

	size_t number_of_hash_in_tree = sorted_hashes.size();
	if(number_of_hash_in_tree %2 != 0) number_of_hash_in_tree++;
	std::vector<size_t> number_of_hashes_in_levels_without_copy_hash;
	std::vector<size_t> number_of_hashes_in_levels;
	number_of_hashes_in_levels.push_back(number_of_hash_in_tree);
	size_t next_level = 0;
	size_t level = number_of_hash_in_tree;
	while(level>2) {
		next_level += level/2;
		number_of_hashes_in_levels_without_copy_hash.push_back(next_level);
		if(next_level %2 != 0) next_level++;
		number_of_hashes_in_levels.push_back(next_level);
		number_of_hash_in_tree += next_level;
		level = next_level;
		next_level = 0;
	}
	number_of_hashes_in_levels.push_back(1);

	tree.resize(static_cast<size_t>(std::pow(2, number_of_hashes_in_levels.size())-1));
	const auto diff = tree.size() - sorted_hashes.size();
	for(size_t i=sorted_hashes.size(); i>0; i--) {
		tree.at(diff+i-1) = sorted_hashes.at(i-1);
	}
	if(sorted_hashes.size() %2 != 0) {
		tree.at(tree.size()-sorted_hashes.size()-1) = sorted_hashes.at(0);
	}
	sorted_hashes.clear();

	std::vector<size_t>number_of_elements_in_levels;
	for(size_t i=number_of_hashes_in_levels.size()-1; i>1; i--){
		number_of_elements_in_levels.push_back(static_cast<size_t>(std::pow(2,i-1)));
	}
	number_of_hashes_in_levels.clear();

	size_t count = 0;
	size_t number_level = 0;
	t_hash_type hash_tmp;

	bool copy_hash = false;
	for(size_t index_tree=tree.size()-1; index_tree>2; index_tree-=2) {
		t_hash_type hash;
		if(count > number_of_hashes_in_levels_without_copy_hash.at(number_level)) hash.fill(0x00);
		else hash = get_hash(tree.at(index_tree-1), tree.at(index_tree));
		const auto index_parent = (index_tree-2)/2;
		if(copy_hash == true) {
			tree.at(index_parent) = hash_tmp;
			copy_hash = false;
		} else tree.at(index_parent) = hash;
		count++;
		if(count==number_of_hashes_in_levels_without_copy_hash.at(number_level)) {
			if(count %2 != 0) {
				hash_tmp = hash;
				copy_hash = true;
			}
		}
		if(count==number_of_elements_in_levels.at(number_level)) {
			count = 0;
			if(number_level < number_of_elements_in_levels.size()-1) number_level++;
		}
	}
	const auto hash = get_hash(tree.at(1), tree.at(2));
	tree.at(0) = hash;
	return tree;
}

std::vector<t_hash_type> c_merkle_tree::get_branch_merkle_tree(const t_hash_type &txid) {
	const auto merkle_tree = get_merkle_tree();
	auto it = std::find(merkle_tree.cbegin(), merkle_tree.cend(), txid);
	if(it==merkle_tree.end()) throw std::runtime_error("there is no such txid in merkle tree");
	std::vector<t_hash_type> branch_merkle_tree;
	if(merkle_tree.size()==1) {
		std::vector<t_hash_type> branch_merkle_tree;
		branch_merkle_tree.clear();
		return branch_merkle_tree;
	}
	auto index = static_cast<size_t>(std::distance(merkle_tree.cbegin(), it));
	do {
		if(index %2 == 0) {
			branch_merkle_tree.insert(branch_merkle_tree.cbegin(), merkle_tree.at(index-1));
			index -= 2;
			index /=2;
		} else {
			branch_merkle_tree.insert(branch_merkle_tree.cbegin(), merkle_tree.at(index+1));
			index--;
			index /=2;
		}
	} while(index>0);
	return branch_merkle_tree;
}
