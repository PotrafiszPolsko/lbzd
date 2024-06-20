#include "crypto.hpp"
#include <iostream>
#include <algorithm>

void c_crypto::set_nonce(const t_nonce_type & nonce) {
	if (m_nonce_size != nonce.size()) throw std::invalid_argument("bad nonce size");
	m_nonce = nonce;
}

void c_crypto::set_dh_keys(const c_keys & keys) {
	m_key_pair = keys;
}

void c_crypto::generate_nonce() {
	m_nonce[m_nonce_size];
	randombytes_buf(&m_nonce[0], m_nonce_size);
}

t_nonce_type c_crypto::get_nonce() const {
	return m_nonce;
}

c_crypto::c_crypto() {
	m_nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
	generate_nonce();
}

std::string c_crypto::encrypt(const std::string &msg) const {
	std::string ciphertext;
	ciphertext.resize(crypto_aead_xchacha20poly1305_IETF_ABYTES + msg.size());
	auto *cipher = reinterpret_cast<unsigned char *>(ciphertext.data());
	const auto *message = reinterpret_cast<const unsigned char *>(msg.data());
	unsigned long long ciphertext_len = 0;
	crypto_aead_xchacha20poly1305_ietf_encrypt(
				cipher,
				&ciphertext_len,
				message,
				msg.size(),
				nullptr,
				0,
				nullptr,
				m_nonce.data(),
				m_key_pair.m_key_transmit.data());
	return ciphertext;
}

std::vector<unsigned char> c_crypto::decrypt(const std::vector<unsigned char> &enc) const {
	std::vector<unsigned char> decrypt;
	if(enc.size()<crypto_aead_xchacha20poly1305_IETF_ABYTES) throw std::invalid_argument("encrypt size is to short");
	decrypt.resize(enc.size() - crypto_aead_xchacha20poly1305_IETF_ABYTES);
	unsigned long long decrypted_len = 0;
	const int ret = crypto_aead_xchacha20poly1305_ietf_decrypt(
				decrypt.data(),
				&decrypted_len,
				nullptr,
				enc.data(),
				enc.size(),
				nullptr,
				0,
				m_nonce.data(),
				m_key_pair.m_key_receive.data());
	if (ret == -1) throw std::runtime_error("decrypt error");
	return decrypt;
}
