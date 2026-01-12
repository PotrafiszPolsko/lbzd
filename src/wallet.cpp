#include <cstdint>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include "logger.hpp"
#include "txid_generate.hpp"
#include "wallet.hpp"
#include "txid_generate.hpp"
#include "utils.hpp"

t_hash_type c_wallet::get_main_pkh() const noexcept {
	const auto main_pk = get_main_pk();
	return generate_hash(main_pk);
}

t_public_key_type c_wallet::get_main_pk() const {
	const auto & root_key = m_key_manager.get_root_key();
	return root_key.m_public_key;
}

t_root_keypair c_wallet::get_main_keypair() const noexcept {
	return m_key_manager.get_root_key();
}

void c_wallet::create_seed_file_if_not_exists() {
	auto wallet_path = m_datadir_path;
	wallet_path /= "wallet";
	auto seed_path = wallet_path;
	seed_path /= "seed";
	if(!std::filesystem::exists(seed_path)) {
		if(!std::filesystem::exists(wallet_path)) {
			if(std::filesystem::create_directories(wallet_path))
				LOG(info) << "Created datadir wallet: " << wallet_path;
			save_entropy_file(seed_path);
			LOG(info) << "Created seed file: " << seed_path;
		} else {
			save_entropy_file(seed_path);
			LOG(info) << "Created seed file: " << seed_path;
		}
	} else {
		LOG(info) << "There is seed file. New seed file is not created";
	}
}

void c_wallet::save_entropy_file(const std::filesystem::path & file_path) const {
	std::fstream entropy_file;
	entropy_file.open(file_path, std::ios::binary | std::ios::out);
	if( entropy_file.good() == false ) throw std::invalid_argument("File in not opened");
	const auto entropy_bytes = m_seed.get_entropy_bytes();
	entropy_file.write(reinterpret_cast<const char *>(entropy_bytes.data()), entropy_bytes.size());
	entropy_file.close();
}

t_signature_type c_wallet::sign_tx_by_main_identity(const c_transaction & tx) const {
	const auto generated_txid = c_txid_generate::generate_txid(tx);
	if (generated_txid != tx.m_txid) throw std::invalid_argument("Bad txid");
	const auto root_key = m_key_manager.get_root_key();
	const auto sign = n_bip32::c_key_manager_BIP32::sign_root(tx.m_txid.data(), tx.m_txid.size(), root_key);
	return sign;
}

t_signature_type c_wallet::sign_message(std::string_view & message) const {
	const auto & root_keypair = m_key_manager.get_root_key();
	return n_bip32::c_key_manager_BIP32::sign_root(reinterpret_cast<const unsigned char *>(message.data()), message.size(), root_keypair);
}

std::array<std::string, n_seedparams::seed_number_of_words> c_wallet::get_words_of_seed() const {
	return m_seed.get_words_of_seed();
}

void c_wallet::generate_seed_from_words(const std::array<std::string, n_seedparams::seed_number_of_words> & seed_words) {
	m_seed.generate_seed_from_words(seed_words);
	const auto entropy_bytes = m_seed.get_entropy_bytes();
	n_bip32::c_key_manager_BIP32 key_manager(entropy_bytes);
	m_key_manager = key_manager;
	auto seed_path = m_datadir_path;
	seed_path /= "wallet";
	seed_path /= "seed";
	save_entropy_file(seed_path);
}

c_transaction c_wallet::get_sign_tx(c_transaction tx) const {
	const auto generated_txid = c_txid_generate::generate_txid(tx);
	if (generated_txid != tx.m_txid) throw std::invalid_argument("Bad txid");
	const auto root_key = m_key_manager.get_root_key();
	tx.m_vin.at(0).m_sign = n_bip32::c_key_manager_BIP32::sign_root(tx.m_txid.data(), tx.m_txid.size(), root_key);
	return tx;
}

c_wallet::c_wallet(const std::filesystem::path & datadir_path)
	:
	  m_datadir_path(datadir_path)
{
	create_seed_file_if_not_exists();
	std::filesystem::path seed_path = datadir_path;
	seed_path /= "wallet";
	seed_path /= "seed";
	std::ifstream entropy_file;
	entropy_file.open(seed_path, std::ios::binary | std::ios::in);
	if( entropy_file.good() == false ) throw std::invalid_argument("File in not opened");
	std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> entropy;
	entropy_file.read(reinterpret_cast<char *>(entropy.data()), entropy.size());
	m_seed.set_entropy_bytes(entropy);
	n_bip32::c_key_manager_BIP32 key_manager(entropy);
	m_key_manager = key_manager;
}

c_wallet::c_wallet(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & entropy, const std::filesystem::path & datadir_path)
	:
	  m_datadir_path(datadir_path),
	  m_seed(c_seed::make_seed_entropy(entropy)),
	  m_key_manager(entropy)
{
}
