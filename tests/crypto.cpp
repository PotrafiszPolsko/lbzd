#include <gtest/gtest.h>
#include "../src/dh.hpp"
#include "../src/crypto.hpp"

TEST(crypto, encrypt_decrypt) {
	c_dh dh_client, dh_server;
	const auto pk_client = dh_client.pk();
	const auto pk_server = dh_server.pk();
	const auto dh_keys_for_client = dh_client.generate_for_client(pk_server);
	const auto dh_keys_for_server = dh_server.generate_for_server(pk_client);
	EXPECT_EQ(dh_keys_for_client.m_key_receive, dh_keys_for_server.m_key_transmit);
	EXPECT_EQ(dh_keys_for_server.m_key_receive, dh_keys_for_client.m_key_transmit);

	c_crypto crypto_client, crypto_server;
	crypto_client.set_dh_keys(dh_keys_for_client);
	crypto_server.set_dh_keys(dh_keys_for_server);

	crypto_client.generate_nonce();
	const auto nonce = crypto_client.get_nonce();
	crypto_server.set_nonce(nonce);
	std::string message;
	message.resize(1000);
	randombytes_buf(message.data(), message.size());

	const auto encrypted_msg = crypto_client.encrypt(message);
	std::vector<unsigned char> encrypted_msg_vector;
	std::transform(
		encrypted_msg.cbegin(),
		encrypted_msg.cend(),
		std::back_inserter(encrypted_msg_vector),
		[](const char c){return static_cast<unsigned char>(c);});
	const auto decrypted_msg_vector = crypto_server.decrypt(encrypted_msg_vector);
	std::string decrypted_msg;
	std::transform(
		decrypted_msg_vector.cbegin(),
		decrypted_msg_vector.cend(),
		std::back_inserter(decrypted_msg),
		[](const unsigned char c){return static_cast<char>(c);});
	EXPECT_EQ(decrypted_msg, message);
}