#ifndef KEY_MANAGER_BIP32_HPP
#define KEY_MANAGER_BIP32_HPP

#include <cstring>
#include <array>
#include <sodium.h>
#include <cmath>
#include <cassert>
#include <algorithm>
#include "utils.hpp"
#include "types.hpp"
#include "params.hpp"

extern "C" {
	#include "ed25519/ed25519.h"
}

class c_seed;

namespace n_bip32 {

class c_key_manager_BIP32 {
	friend class ::c_seed;
	public:
		c_key_manager_BIP32();
		c_key_manager_BIP32(const std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> & seed_entropy);
		const t_root_keypair & get_root_key() const;
		static t_signature_type sign_root(const unsigned char * const data, size_t data_size, const t_root_keypair & keypair) noexcept;
		static bool verify(const unsigned char * const data,
							size_t data_size, const std::array<unsigned char,
							crypto_sign_BYTES> & signature,
							const t_public_key_type & public_key) noexcept;
	private:
		c_key_manager_BIP32(const std::array<unsigned char, 32> & master_secret);
		t_secret_key_root generate_secret_root_key(const std::array<unsigned char, 32> & master_secret) const;
		template<class T_SECRET_KEY>
		t_public_key_type generate_public_key_from_master_secert(const T_SECRET_KEY & master_secret_key) const noexcept;
		std::array<unsigned char, crypto_hash_sha256_BYTES> generate_root_chain_code(const t_secret_key_root & master_secret_key) const noexcept;
		t_root_keypair generate_root_key() const;
		t_root_keypair generate_root_key(const std::array<unsigned char, 32> & master_secret) const;
		bool check_k_l_valid(const std::array<unsigned char, 32> & k_l) const;
		t_root_keypair m_root_key;
};

template<class T_SECRET_KEY>
t_public_key_type c_key_manager_BIP32::generate_public_key_from_master_secert(const T_SECRET_KEY & master_secret_key) const noexcept {
	t_public_key_type public_key;
	crypto_scalarmult_ed25519_base(public_key.data(), master_secret_key.m_kl.data());
	return public_key;
}

} // namespace

#endif // KEY_MANAGER_BIP32_HPP
