#include "key_manager_bip32.hpp"
#include "seed.hpp"

namespace n_bip32 {

c_key_manager_BIP32::c_key_manager_BIP32()
	:
	  m_root_key(generate_root_key())
{
}

c_key_manager_BIP32::c_key_manager_BIP32(const std::array<unsigned char, 32> & master_secret)
	:
	  m_root_key(generate_root_key(master_secret))
{
}

c_key_manager_BIP32::c_key_manager_BIP32(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & seed_entropy) {
	const auto seed = c_seed::make_seed_entropy(seed_entropy);
	const auto master_secret = seed.get_seed();
	m_root_key = generate_root_key(master_secret);
}

const t_root_keypair & c_key_manager_BIP32::get_root_key() const {
	return m_root_key;
}

t_signature_type c_key_manager_BIP32::sign_root(const unsigned char * const data, size_t data_size, const t_root_keypair &keypair) noexcept {
	std::array<unsigned char, crypto_sign_BYTES> signature;
	ed25519_sign(signature.data(), data, data_size, keypair.m_public_key.data(), keypair.m_secret_key.m_kl.data(), keypair.m_secret_key.m_kr.data());
	return signature;
}

bool c_key_manager_BIP32::verify(const unsigned char * const data, size_t data_size, const std::array<unsigned char, crypto_sign_BYTES> & signature, const t_public_key_type & public_key) noexcept {
	return ed25519_verify(signature.data(), data, data_size, public_key.data());
}

bool c_key_manager_BIP32::check_k_l_valid(const std::array<unsigned char, 32> & k_l) const {
	const auto last_byte = k_l.back();
	const auto mask {static_cast<unsigned char>(0b00100000)};
	if ((last_byte & mask) == static_cast<unsigned char>(0x00)) return true;
	else return false;
}

t_secret_key_root c_key_manager_BIP32::generate_secret_root_key(const std::array<unsigned char, 32> & master_secret) const {
	t_secret_key_root secret_key;
	secret_key.m_master_secret = master_secret;
	std::array<unsigned char, 64> k; // sha512(m_master_secert)
	crypto_hash_sha512(k.data(), secret_key.m_master_secret.data(), secret_key.m_master_secret.size());
	std::copy_n(k.cbegin(), 32, secret_key.m_kl.begin());
	if (!check_k_l_valid(secret_key.m_kl)) throw std::invalid_argument("Bad master secret (k_l not valid)");
	std::copy_n(k.cbegin() + 32, 32, secret_key.m_kr.begin());
	assert((k.at(31) & static_cast<unsigned char>(0b00100000)) == static_cast<unsigned char>(0x00));
	secret_key.m_kl.at(0) &= static_cast<unsigned char>(0b11111000);
	secret_key.m_kl.at(31) &= static_cast<unsigned char>(0b01111111);
	secret_key.m_kl.at(31) |= static_cast<unsigned char>(0b01000000);
	return secret_key;
}

std::array<unsigned char, crypto_hash_sha256_BYTES> c_key_manager_BIP32::generate_root_chain_code(const t_secret_key_root & master_secret_key) const noexcept {
	std::array<unsigned char, crypto_hash_sha256_BYTES> c; // root chain code
	crypto_hash_sha256_state state;
	crypto_hash_sha256_init(&state);
	const unsigned char first_byte{0x01};
	crypto_hash_sha256_update(&state, &first_byte, 1);
	crypto_hash_sha256_update(&state, master_secret_key.m_master_secret.data(), master_secret_key.m_master_secret.size());
	crypto_hash_sha256_final(&state, c.data());
	return c;
}

t_root_keypair c_key_manager_BIP32::generate_root_key() const {
	c_seed seed;
	const auto master_secret = seed.get_seed();
	t_root_keypair root_keypair;
	root_keypair.m_secret_key = generate_secret_root_key(master_secret);
	root_keypair.m_public_key = generate_public_key_from_master_secert(root_keypair.m_secret_key);
	root_keypair.m_c = generate_root_chain_code(root_keypair.m_secret_key);
	return root_keypair;
}

t_root_keypair c_key_manager_BIP32::generate_root_key(const std::array<unsigned char, 32> & master_secret) const {
	t_root_keypair root_keypair;
	root_keypair.m_secret_key = generate_secret_root_key(master_secret);
	root_keypair.m_public_key = generate_public_key_from_master_secert(root_keypair.m_secret_key);
	root_keypair.m_c = generate_root_chain_code(root_keypair.m_secret_key);
	return root_keypair;
}

} // namespce
