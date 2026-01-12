#include "wallet_module.hpp"
#include "logger.hpp"

void c_wallet_module::run() {
	LOG(info) << "Run wallet module";
}

t_public_key_type c_wallet_module::get_main_pk() const {
	return m_wallet->get_main_pk();
}

t_signature_type c_wallet_module::sign_tx_by_main_identity(const c_transaction & tx) const {
	return m_wallet->sign_tx_by_main_identity(tx);
}

t_signature_type c_wallet_module::sign_message_using_main_pk(std::string_view msg) const {
	return m_wallet->sign_message(msg);
}

std::array<std::string, n_seedparams::seed_number_of_words> c_wallet_module::get_words_of_seed() const {
	return m_wallet->get_words_of_seed();
}

void c_wallet_module::generate_seed_from_words(const std::array<std::string, n_seedparams::seed_number_of_words> & seed_words) {
	m_wallet->generate_seed_from_words(seed_words);
}

c_wallet_module::c_wallet_module(c_mediator &mediator, std::unique_ptr<c_wallet> &&wallet)
:
	c_wallet_module_interface(mediator),
	m_wallet(std::move(wallet))
{
}

c_wallet_module::c_wallet_module(c_mediator & mediator)
:
	c_wallet_module_interface(mediator),
	m_wallet()
{
}

c_wallet_module_interface::c_wallet_module_interface(c_mediator &mediator)
:
	c_component(mediator)
{
}
