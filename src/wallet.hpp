#ifndef WALLET_HPP
#define WALLET_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <map>
#include <sodium.h>
#include <filesystem>
#include <string_view>
#include "key_manager_bip32.hpp"
#include "transaction.hpp"
#include "types.hpp"
#include "seed.hpp"

class c_wallet {
	public:
		c_wallet() = default; // generate new wallet without save to file (for test/simulation only)
		c_wallet(const std::filesystem::path & datadir_path);
		c_wallet(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy, const std::filesystem::path & datadir_path);
		virtual ~c_wallet() = default; //only for tests
		t_hash_type get_main_pkh() const noexcept;
		virtual t_public_key_type get_main_pk() const;
		t_root_keypair get_main_keypair() const noexcept;
		virtual t_signature_type sign_tx_by_main_identity(const c_transaction & tx) const;
		virtual t_signature_type sign_message(std::string_view & message) const;
		virtual std::array<std::string, n_seedparams::seed_number_of_words> get_words_of_seed() const;
		virtual void generate_seed_from_words(const std::array<std::string, n_seedparams::seed_number_of_words> & seed_words);
		c_transaction get_sign_tx(c_transaction tx) const;
		virtual void save_entropy_file(const std::filesystem::path & file_path) const;
	private:

		std::filesystem::path m_datadir_path;
		std::filesystem::path m_seed_path;
		c_seed m_seed;
		n_bip32::c_key_manager_BIP32 m_key_manager;

		void create_seed_file_if_not_exists();
};

#endif // WALLET_HPP
