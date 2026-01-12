#ifndef SEED_HPP
#define SEED_HPP

#include <sodium.h>
#include <array>
#include <vector>
#include <bitset>
#include <stdexcept>
#include <algorithm>
#include <boost/dynamic_bitset.hpp>
#include "params.hpp"
#include "words.hpp"
#include "key_manager_bip32.hpp"

class c_seed {
	public:
		c_seed();
		static c_seed make_seed_entropy(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy);
		void generate_seed_from_words(const std::array<std::string, n_seedparams::seed_number_of_words> & user_words);
		void generate_seed();
		std::array<unsigned char, n_seedparams::seed_number_of_bytes> get_seed() const;
		std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> get_entropy_bytes() const;
		void set_entropy_bytes(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy);
		std::array<std::string, n_seedparams::seed_number_of_words> get_words_of_seed() const;

	private:
		c_seed(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy);
		std::array<std::string, n_seedparams::seed_number_of_words> m_mnemonic_sentence_array;
		std::array<unsigned char, n_seedparams::seed_number_of_bytes> m_seed;

		std::array<std::string, n_seedparams::seed_number_of_words> get_seed_words(std::vector<bool> &full_bits) const;
		std::array<bool, n_seedparams::seed_number_of_entropy_bytes*8> array_bytes_to_array_bits(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & bytes_array) const;
		bool check_checksum(const std::array<std::string, n_seedparams::seed_number_of_words> & user_words) const;
		std::vector<uint16_t> seed_words_to_integers(const std::array<std::string, n_seedparams::seed_number_of_words> & user_words) const;
		std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> vector_numbers_of_words_to_array_bytes(const std::vector<uint16_t> &numbers_of_words) const;
		std::array<bool, n_seedparams::seed_number_of_csum_bits> get_last_N_bits_of_user_words(const std::vector<uint16_t> &numbers_of_words) const;
		std::array<unsigned char, crypto_hash_sha256_BYTES> generate_hash(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy) const;

		template<size_t N>
		std::array<bool, N> get_additional_bits(const unsigned char byte) const;
		template<size_t N>
		std::array<bool, N> bits_string_to_bits_array(const std::string & str) const;
		template<size_t N>
		std::array<bool, N> int_to_bits_array(const size_t number) const;

};

template<size_t N>
std::array<bool, N> c_seed::bits_string_to_bits_array(const std::string & str) const {
	std::array<bool, N> bits_array;
	for(size_t i=0; i<str.size(); i++){
		if(str.at(i)=='0') bits_array.at(i) = false;
		else if(str.at(i)=='1') bits_array.at(i) = true;
		else throw std::invalid_argument("must be bit: 1 or 0");
	}
	return bits_array;
}

template<size_t N>
std::array<bool, N> c_seed::get_additional_bits(const unsigned char byte) const {
	std::bitset<N> bits{std::to_integer<unsigned int>(static_cast<std::byte>(byte))};
	auto bits_as_string = bits.to_string();
	const auto bits_array = bits_string_to_bits_array<N>(bits_as_string);
	return bits_array;
}

template<size_t N>
std::array<bool, N> c_seed::int_to_bits_array(const size_t number) const {
	std::bitset<n_seedparams::seed_bits_of_one_word>bits_number{number};
	const auto bits_str_number = bits_number.to_string();
	const auto bits_arr_number = bits_string_to_bits_array<n_seedparams::seed_bits_of_one_word>(bits_str_number);
	return bits_arr_number;
}
#endif // SEED_HPP

