#ifndef C_CRYPTO_HPP
#define C_CRYPTO_HPP

#include "keys.hpp"
#include "types.hpp"
#include <vector>
#include <string>

/**
XChaCha20-Poly1305-IETF
*/

class c_crypto {
	public:
		c_crypto();
		std::string encrypt(const std::string & msg) const;
		std::vector<unsigned char> decrypt(const std::vector<unsigned char> & enc) const;
		void set_nonce(const t_nonce_type & nonce);
		void set_dh_keys(const c_keys & keys);
		void generate_nonce();
		t_nonce_type get_nonce() const;

	private:
		c_keys m_key_pair;
		t_nonce_type m_nonce;
		size_t m_nonce_size;
	};


#endif // C_CRYPTO_HPP
