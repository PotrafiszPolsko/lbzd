#ifndef WALLET_MODULE_INTERFACE_HPP
#define WALLET_MODULE_INTERFACE_HPP

#include "component.hpp"

class c_wallet_module_interface : public c_component {
	public:
		c_wallet_module_interface(c_mediator & mediator);
		virtual ~c_wallet_module_interface() = default;
		virtual t_public_key_type get_main_pk() const = 0;
		virtual t_signature_type sign_message_using_main_pk(std::string_view msg) const = 0;
		virtual t_signature_type sign_tx_by_main_identity(const c_transaction & tx) const = 0;
		virtual std::array<std::string, n_seedparams::seed_number_of_words> get_words_of_seed() const = 0;
		virtual void generate_seed_from_words(const std::array<std::string, n_seedparams::seed_number_of_words> & seed_words) = 0;
};

#endif // WALLET_MODULE_INTERFACE_HPP
