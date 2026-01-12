#include "seed.hpp"

c_seed::c_seed() {
	do {
		try {
			generate_seed();
			const auto entropy_bytes = get_entropy_bytes();
			n_bip32::c_key_manager_BIP32 key_manager(entropy_bytes); // try to generate keys from seed bytes
			break;
		} catch (const std::exception &) {}
	} while(true);
}

c_seed c_seed::make_seed_entropy(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> &entropy) {
	c_seed seed(entropy);
	return seed;
}

c_seed::c_seed(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy) {
	set_entropy_bytes(entropy);
	n_bip32::c_key_manager_BIP32 key_manager(m_seed); // try to generate keyst from seed bytes
}

void c_seed::generate_seed_from_words(const std::array<std::string, n_seedparams::seed_number_of_words> & user_words) {
	if(check_checksum(user_words)==false) throw std::invalid_argument("bad mnemonic sentence");
	m_mnemonic_sentence_array = user_words;
	std::string mnemonic_sentence;
	std::array<unsigned char, crypto_pwhash_SALTBYTES> salt;
	salt.fill(0x00);
	for(const auto &word:user_words) mnemonic_sentence+=word;
	if(crypto_pwhash(m_seed.data(), m_seed.size(), mnemonic_sentence.data(), mnemonic_sentence.size(), salt.data(),
					 crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_ALG_DEFAULT) != 0)
		throw std::runtime_error("out of memory");
}

void c_seed::generate_seed() {
	std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> entropy;
	crypto_secure_random(entropy.data(), entropy.size());
	const auto entropy_as_bits = array_bytes_to_array_bits(entropy);
	const auto hash_bin = generate_hash(entropy);
	const auto additional_bit = get_additional_bits<n_seedparams::seed_number_of_csum_bits>(hash_bin.at(0));
	std::vector<bool> full_bits;
	std::copy(entropy_as_bits.cbegin(), entropy_as_bits.cend(), std::back_inserter(full_bits));
	std::copy(additional_bit.cbegin(), additional_bit.cend(), std::back_inserter(full_bits));
	m_mnemonic_sentence_array = get_seed_words(full_bits);
	generate_seed_from_words(m_mnemonic_sentence_array);

}

std::array<std::string, n_seedparams::seed_number_of_words> c_seed::get_seed_words(std::vector<bool> &full_bits) const {
	std::array<std::string, n_seedparams::seed_number_of_words> words;
	for (size_t i = 0; i < n_seedparams::seed_number_of_words; i++) {
		uint16_t word_number = 0;
		for (size_t j = 0; j < n_seedparams::seed_bits_of_one_word; j++) {
			bool bit = full_bits.front();
			full_bits.erase(full_bits.begin());
			word_number <<= 1;
			word_number |= bit;
		}
		words.at(i)=g_seed_all_words.at(word_number);
	}
	return words;
}

std::array<bool, n_seedparams::seed_number_of_entropy_bytes*8> c_seed::array_bytes_to_array_bits(const std::array<unsigned char,
																						 n_seedparams::seed_number_of_entropy_bytes> &bytes_array) const {
	std::array<bool, n_seedparams::seed_number_of_entropy_bytes*8> bits_array;
	for(size_t i=0; i<bytes_array.size(); i++){
		const auto bin_vec = get_additional_bits<8>(bytes_array.at(i));
		std::copy(bin_vec.cbegin(), bin_vec.cend(), bits_array.begin()+i*8);
	}
	return bits_array;
}

bool c_seed::check_checksum(const std::array<std::string, n_seedparams::seed_number_of_words> &user_words) const {
	const auto numbers_of_words = seed_words_to_integers(user_words);
	const auto entropy = vector_numbers_of_words_to_array_bytes(numbers_of_words);
	const auto last_bits_of_user_words = get_last_N_bits_of_user_words(numbers_of_words);
	const auto hash = generate_hash(entropy);
	const auto bits = get_additional_bits<n_seedparams::seed_number_of_csum_bits>(hash.at(0));
	if(bits==last_bits_of_user_words) return true;
	else return false;
}

std::vector<uint16_t> c_seed::seed_words_to_integers(const std::array<std::string, n_seedparams::seed_number_of_words> &user_words) const {
	std::vector<uint16_t> number_of_words;
	for(const auto &word:user_words) {
		const auto iterator = std::find(g_seed_all_words.cbegin(), g_seed_all_words.cend(), word);
		const auto number_of_word = static_cast<uint16_t>(std::distance(g_seed_all_words.cbegin(), iterator));
		number_of_words.push_back(number_of_word);
	}
	return number_of_words;
}

std::array<std::string, n_seedparams::seed_number_of_words> c_seed::get_words_of_seed() const {
	return m_mnemonic_sentence_array;
}

std::array<unsigned char, n_seedparams::seed_number_of_bytes> c_seed::get_seed() const {
	return m_seed;
}

std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> c_seed::get_entropy_bytes() const {
	const auto number_of_words = seed_words_to_integers(m_mnemonic_sentence_array);
	const auto entropy = vector_numbers_of_words_to_array_bytes(number_of_words);
	return entropy;
}

void c_seed::set_entropy_bytes(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy) {
	const auto entropy_as_bits = array_bytes_to_array_bits(entropy);
	const auto hash_bin = generate_hash(entropy);
	const auto additional_bit = get_additional_bits<n_seedparams::seed_number_of_csum_bits>(hash_bin.at(0));
	std::vector<bool> full_bits;
	std::copy(entropy_as_bits.cbegin(), entropy_as_bits.cend(), std::back_inserter(full_bits));
	std::copy(additional_bit.cbegin(), additional_bit.cend(), std::back_inserter(full_bits));
	m_mnemonic_sentence_array = get_seed_words(full_bits);
	generate_seed_from_words(m_mnemonic_sentence_array);
}

std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> c_seed::vector_numbers_of_words_to_array_bytes(const std::vector<uint16_t> &numbers_of_words) const {
	if(numbers_of_words.size()!=n_seedparams::seed_number_of_words) throw std::invalid_argument("bad number of words");
	std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> byte_words;
	std::vector<bool> vec_bits_number;
	for(const auto &number:numbers_of_words) {
		const auto bits_arr_number = int_to_bits_array<n_seedparams::seed_bits_of_one_word>(number);
		std::copy(bits_arr_number.cbegin(), bits_arr_number.cend(), std::back_inserter(vec_bits_number));
	}
	for(size_t i=0; i<n_seedparams::seed_number_of_entropy_bytes; i++) {
		uint8_t byte{0x00};
		for(size_t i=0; i<8; i++){
			byte <<= 1;
			byte |= vec_bits_number.at(0);
			vec_bits_number.erase(vec_bits_number.begin());
		}
		byte_words.at(i)=byte;
	}
	return byte_words;
}

std::array<bool, n_seedparams::seed_number_of_csum_bits> c_seed::get_last_N_bits_of_user_words(const std::vector<uint16_t> &numbers_of_words) const {
	if(numbers_of_words.size()!=n_seedparams::seed_number_of_words) throw std::invalid_argument("bad number of words");
	const auto bits_arr_number = int_to_bits_array<n_seedparams::seed_bits_of_one_word>(numbers_of_words.back());
	std::array<bool, n_seedparams::seed_number_of_csum_bits> arr_of_last_4_bits;
	std::copy_n(bits_arr_number.cend()-n_seedparams::seed_number_of_csum_bits, n_seedparams::seed_number_of_csum_bits, arr_of_last_4_bits.begin());
	return arr_of_last_4_bits;
}

std::array<unsigned char, crypto_hash_sha256_BYTES> c_seed::generate_hash(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> &entropy) const {
	std::array<unsigned char, crypto_hash_sha256_BYTES> hash;
	crypto_hash_sha256(hash.data(), entropy.data(), entropy.size());
	return hash;
}
