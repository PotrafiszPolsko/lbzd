#ifndef C_DH_HPP
#define C_DH_HPP

#include "keys.hpp"

class c_dh {
		std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> m_pk;
		std::array<unsigned char, crypto_kx_SECRETKEYBYTES> m_sk;

	public:
		c_keys generate_for_client(const std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> & server_pk);
		c_keys generate_for_server(const std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> & client_pk);
		std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> pk();
		c_dh();
	};


#endif // C_DH_HPP
