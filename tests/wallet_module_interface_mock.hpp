#ifndef WALLET_MODULE_INTERFACE_MOCK_HPP
#define WALLET_MODULE_INTERFACE_MOCK_HPP

#include <gmock/gmock.h>
#include "../src/wallet_module_interface.hpp"
#include "mediator_stub.hpp"

class c_wallet_module_mock : public c_wallet_module_interface {
	public:
		c_wallet_module_mock();
		MOCK_METHOD(void, run, (), (override));
		MOCK_METHOD(t_public_key_type, get_main_pk, (), (const, override));
		MOCK_METHOD(t_signature_type, sign_message_using_main_pk, (std::string_view msg), (const, override));
		MOCK_METHOD(t_signature_type, sign_tx_by_main_identity, (const c_transaction & tx), (const, override));
		using array_seed_words = std::array<std::string, n_seedparams::seed_number_of_words>;
		MOCK_METHOD(array_seed_words, get_words_of_seed, (), (const, override));
		MOCK_METHOD(void, generate_seed_from_words, (const array_seed_words & seed_words), (override));
	private:
		static c_mediator_stub m_mediator_stub;
};

#endif // WALLET_MODULE_INTERFACE_MOCK_HPP
