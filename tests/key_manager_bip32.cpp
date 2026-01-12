#include <gtest/gtest.h>
#include "../src/key_manager_bip32.hpp"

TEST(key_manager, generate_root_key) {
		n_bip32::c_key_manager_BIP32 key_manager;
		const auto root_keypair = key_manager.get_root_key();
		std::string data_to_sign = "message";
		const auto sign = key_manager.sign_root(reinterpret_cast<const unsigned char *>(data_to_sign.data()),  data_to_sign.size(), root_keypair);
		EXPECT_TRUE(key_manager.verify(reinterpret_cast<const unsigned char*>(data_to_sign.data()), data_to_sign.size(), sign, root_keypair.m_public_key));
}
