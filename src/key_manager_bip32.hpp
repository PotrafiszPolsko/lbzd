#ifndef KEY_MANAGER_BIP32_HPP
#define KEY_MANAGER_BIP32_HPP

#include <sodium.h>
#include "types.hpp"

extern "C" {
	#include "ed25519/ed25519.h"
}

namespace n_bip32 {

class c_key_manager_BIP32 {
	public:
		static bool verify(const unsigned char * const data,
							size_t data_size, const std::array<unsigned char,
							crypto_sign_BYTES> & signature,
							const t_public_key_type & public_key) noexcept;
};

} // namespace

#endif // KEY_MANAGER_BIP32_HPP
