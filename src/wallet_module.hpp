#ifndef C_WALLET_MODULE_HPP
#define C_WALLET_MODULE_HPP

#include "wallet_module_interface.hpp"
#include "wallet.hpp"

class c_wallet_module final : public c_wallet_module_interface {
	friend class c_wallet_module_builder;
	friend std::unique_ptr<c_wallet_module> std::make_unique<c_wallet_module>(c_mediator &);
	public:
		void run() override;
		t_public_key_type get_main_pk() const override;
		t_signature_type sign_tx_by_main_identity(const c_transaction & tx) const override;
		t_signature_type sign_message_using_main_pk(std::string_view msg) const override;
		std::array<std::string, n_seedparams::seed_number_of_words> get_words_of_seed() const override;
		void generate_seed_from_words(const std::array<std::string, n_seedparams::seed_number_of_words> & seed_words) override;
		c_wallet_module(c_mediator & mediator, std::unique_ptr<c_wallet> &&wallet);
	private:
		c_wallet_module(c_mediator & mediator);
		std::unique_ptr<c_wallet> m_wallet;
};

#endif // C_WALLET_MODULE_HPP
