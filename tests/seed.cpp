#include <gtest/gtest.h>
#include "../src/params.hpp"

class seed : public ::testing::TestWithParam<unsigned int> {
};
INSTANTIATE_TEST_SUITE_P(generate_seed, seed, testing::Range(0u, 100u),
						 testing::PrintToStringParamName());

TEST_P(seed, generate_seed_from_word) {
	c_seed seed;
	EXPECT_NO_THROW(seed.generate_seed());
	const auto words = seed.get_words_of_seed();
	for(const auto &word:words) {
		EXPECT_NE(std::find(g_seed_all_words.cbegin(), g_seed_all_words.cend(), word), g_seed_all_words.cend());
	}
	c_seed seed2;
	seed2.generate_seed_from_words(words);
	EXPECT_EQ(seed.get_seed(), seed2.get_seed());
}

TEST_P(seed, generate_seed_from_bad_word_of_user) {
	c_seed seed;
	std::array<std::string, n_seedparams::seed_number_of_words> words ={
		"dfdssa",
		"gfdgfdg",
		"htytr",
		"rytrh",
		"hgfuyt",
		"nhjytjytj",
		"nhytu",
		"bcbc",
		"juoiuyiyt",
		"qwretdg",
		"btgghtrw",
		"tgfjyteutye"
	};
	EXPECT_THROW(seed.generate_seed_from_words(words), std::invalid_argument);
}

TEST_P(seed, check_checksum) {
	c_seed seed;
	std::array<std::string, n_seedparams::seed_number_of_words> words ={
		"abandon",
		"ability",
		"able",
		"about",
		"above",
		"absent",
		"absorb",
		"abstract",
		"absurd",
		"abuse",
		"access",
		"accident"
	};
	EXPECT_THROW(seed.generate_seed_from_words(words), std::invalid_argument);
}

TEST(seed, set_entropy) {
	c_seed seed;
	seed.generate_seed();
	const auto entropy_binary = seed.get_entropy_bytes();
	c_seed seed2;
	seed2.set_entropy_bytes(entropy_binary);
	EXPECT_EQ(seed.get_words_of_seed(), seed2.get_words_of_seed());
	EXPECT_EQ(seed.get_entropy_bytes(), seed2.get_entropy_bytes());
}
