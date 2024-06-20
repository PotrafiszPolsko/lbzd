#include "key_manager_bip32.hpp"

extern "C" {
	#include "ed25519/ge.h"
}

namespace n_bip32 {

bool c_key_manager_BIP32::verify(const unsigned char * const data, size_t data_size, const std::array<unsigned char, crypto_sign_BYTES> & signature, const t_public_key_type & public_key) noexcept {
	return ed25519_verify(signature.data(), data, data_size, public_key.data());
}

} // namespce
