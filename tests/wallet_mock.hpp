#ifndef WALLET_MOCK_HPP
#define WALLET_MOCK_HPP

#include "../src/wallet.hpp"
#include <gmock/gmock.h>

class c_wallet_mock : public c_wallet {
	public:
		c_wallet_mock() = default;
		MOCK_METHOD(t_public_key_type, get_main_pk, (), (const, override));
		MOCK_METHOD(t_signature_type, sign_tx_by_main_identity, (const c_transaction & tx), (const, override));
		MOCK_METHOD(t_signature_type, sign_message, (std::string_view & message), (const, override));
		using seed_words_arr = std::array<std::string, n_seedparams::seed_number_of_words>;
		MOCK_METHOD(seed_words_arr, get_words_of_seed, (), (const, override));
		MOCK_METHOD(void, save_entropy_file, (const std::filesystem::path & file_path), (const, override));
		MOCK_METHOD(void, generate_seed_from_words, (const seed_words_arr & seed_words), (override));
};
#endif // WALLET_MOCK_HPP
