#include <gtest/gtest.h>
#include <algorithm>
#include <random>
#include "../src/wallet.hpp"
#include "../src/mempool.hpp"
#include "../src/utxo.hpp"
#include "../src/blockchain.hpp"
#include "../src/merkle_tree.hpp"

class merkle : public ::testing::TestWithParam<unsigned int> {};

#ifdef COVERAGE_TESTS
      const unsigned int limit_to_paramtest_object_to_hashes = 30;
#elif IVOTING_TESTS
      const unsigned int limit_to_paramtest_object_to_hashes = 1000;
#endif

INSTANTIATE_TEST_SUITE_P(amount_hashes, merkle, testing::Range(1u, limit_to_paramtest_object_to_hashes),
						 testing::PrintToStringParamName());
TEST_P(merkle, merkle_tree) {
	c_merkle_tree mt;
	std::vector<std::string> objects_to_hashes;

	const unsigned int n_hashes = GetParam();

	std::array<unsigned char, crypto_generichash_BYTES> hash;

	std::random_device rd;
	std::mt19937 gen(rd());
	std::string obj_to_hash;

	for(size_t j=0; j<n_hashes; j++) {
		for(size_t i=0; i<10; i++) {
			std::uniform_int_distribution<> distribution(0, 1000);
			auto gen_char = distribution(gen);
			obj_to_hash+=gen_char;
		}
		objects_to_hashes.push_back(obj_to_hash);
		obj_to_hash.erase();
	}

	for(size_t i=0; i<n_hashes; i++) {
		crypto_generichash(hash.data(), hash.size(),
						   reinterpret_cast<unsigned char*>(objects_to_hashes[i].data()), objects_to_hashes[i].size(),
						   nullptr, 0);
		mt.add_hash(hash);
	}
	const auto tree_mt = mt.get_merkle_tree();

}

class merkle_bad_hash : public ::testing::TestWithParam<unsigned int> {};
INSTANTIATE_TEST_SUITE_P(bad_one_hash, merkle_bad_hash, testing::Range(2u, limit_to_paramtest_object_to_hashes),
						 testing::PrintToStringParamName());
TEST_P(merkle_bad_hash, bad_hash) {
	c_merkle_tree mt;
	std::vector<std::string> objects_to_hashes;

	const unsigned int n_hashes = GetParam();

	std::array<unsigned char, crypto_generichash_BYTES> hash;

	std::random_device rd;
	std::mt19937 gen(rd());
	std::string obj_to_hash;

	for(size_t j=0; j<n_hashes; j++) {
		for(size_t i=0; i<10; i++) {
			std::uniform_int_distribution<> distribution(0, 1000);
			auto gen_char = distribution(gen);
			obj_to_hash+=gen_char;
		}
		objects_to_hashes.push_back(obj_to_hash);
		obj_to_hash.erase();
	}

	for(size_t i=0; i<n_hashes; i++) {
		crypto_generichash(hash.data(), hash.size(),
						   reinterpret_cast<unsigned char*>(objects_to_hashes[i].data()), objects_to_hashes[i].size(),
						   nullptr, 0);
		mt.add_hash(hash);
	}
	auto tree_mt = mt.get_merkle_tree();
	auto neg = ~tree_mt.at(1).at(3);
	tree_mt.at(1).at(3)=neg;

}

TEST(merkle_empty_hash, bad_hash) {
	c_merkle_tree mt;

	EXPECT_THROW(mt.get_merkle_tree(), std::logic_error);
}

class merkle_branch : public ::testing::TestWithParam<unsigned int> {};
INSTANTIATE_TEST_SUITE_P(branch_merkle_tree, merkle_branch, testing::Range(2u, limit_to_paramtest_object_to_hashes/10),
						 testing::PrintToStringParamName());
TEST_P(merkle_branch, branch_merkle_tree) {
	c_merkle_tree mt;
	std::vector<std::string> objects_to_hashes;

	const unsigned int n_hashes = GetParam();

	std::array<unsigned char, crypto_generichash_BYTES> hash;

	std::random_device rd;
	std::mt19937 gen(rd());
	std::string obj_to_hash;

	for(size_t j=0; j<n_hashes; j++) {
		for(size_t i=0; i<10; i++) {
			std::uniform_int_distribution<> distribution(0, 1000);
			auto gen_char = distribution(gen);
			obj_to_hash+=gen_char;
		}
		objects_to_hashes.push_back(obj_to_hash);
		obj_to_hash.erase();
	}
	std::vector<t_hash_type> hashes;
	for(size_t i=0; i<n_hashes; i++) {
		crypto_generichash(hash.data(), hash.size(),
						   reinterpret_cast<unsigned char*>(objects_to_hashes[i].data()), objects_to_hashes[i].size(),
						   nullptr, 0);
		mt.add_hash(hash);
		hashes.push_back(hash);
	}
	
	const auto tree_mt = mt.get_merkle_tree();
	
	for (const auto & hash : hashes) {
		auto branch_merkle = mt.get_branch_merkle_tree(hash);
		t_hash_type merkle_root = hash;
		while (!branch_merkle.empty()) {
			merkle_root = get_hash(merkle_root, branch_merkle.back());
			branch_merkle.pop_back();
		}
		EXPECT_EQ(merkle_root, tree_mt.at(0));
	}
}

TEST(merkle_branch, branch_merkle_empty) { //branch merkle from merkle_tree with one element (only 1 txid)
	std::array<unsigned char, crypto_generichash_BYTES> hash;

	std::random_device rd;
	std::mt19937 gen(rd());
	std::string obj_to_hash;
	for(size_t i=0; i<10; i++) {
		std::uniform_int_distribution<> distribution(0, 1000);
		auto gen_char = distribution(gen);
		obj_to_hash+=gen_char;
	}

	crypto_generichash(hash.data(), hash.size(),
					reinterpret_cast<unsigned char*>(obj_to_hash.data()), obj_to_hash.size(),
					nullptr, 0);
	
	
	c_merkle_tree mt;
	mt.add_hash(hash);

	const auto tree_mt = mt.get_merkle_tree();
	EXPECT_EQ(tree_mt.size(), 1);
	const auto branch_merkle = mt.get_branch_merkle_tree(hash);
	EXPECT_EQ(branch_merkle.size(), 0);
}

TEST(wallet, reproduce_keys) {
	c_wallet wallet;
	t_voting_mix_data voting_mix_data;
	voting_mix_data.m_number_voting = 0;
	voting_mix_data.m_number_mix = 2;
	const auto pk1 = wallet.get_pk(voting_mix_data);
	const auto pk2 = wallet.get_pk(voting_mix_data);
	EXPECT_EQ(pk1, pk2);
}

TEST(wallet, sign_message) {
	c_wallet wallet;
	std::string_view msg = {"message to sign"};
	const auto sign = wallet.sign_message(msg);
	const auto pk = wallet.get_main_pk();
	EXPECT_TRUE(n_bip32::c_key_manager_BIP32::verify(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), sign, pk));
}

TEST(wallet, get_words_of_seed) {
	c_wallet wallet;
	const auto seed_words = wallet.get_words_of_seed();
	EXPECT_EQ(seed_words.size(), n_seedparams::seed_number_of_words);
	for(const auto &word:seed_words)
		EXPECT_NE(std::find(g_seed_all_words.cbegin(), g_seed_all_words.cend(), word), g_seed_all_words.cend());
}

TEST(wallet, generate_seed_from_words) {
	const std::filesystem::path datadir_path = "./ivoting-test";
	std::filesystem::remove_all(datadir_path);
	c_wallet wallet(datadir_path);
	const auto seed_words = wallet.get_words_of_seed();
	std::filesystem::remove_all(datadir_path / "wallets/seed");
	EXPECT_NO_THROW(wallet.generate_seed_from_words(seed_words));
	const auto seed_words_from_seed = wallet.get_words_of_seed();
	EXPECT_EQ(seed_words_from_seed.size(), n_seedparams::seed_number_of_words);
	for(const auto &word:seed_words_from_seed)
		EXPECT_NE(std::find(g_seed_all_words.cbegin(), g_seed_all_words.cend(), word), g_seed_all_words.cend());
	std::filesystem::remove_all(datadir_path);
}

