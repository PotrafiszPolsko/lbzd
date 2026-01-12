#include <gtest/gtest.h>
#include "../src/wallet_module.hpp"
#include "wallet_mock.hpp"
#include "mediator_mock.hpp"

TEST(wallet_module, get_main_pk) {
	std::unique_ptr<c_wallet> wallet = std::make_unique<c_wallet_mock>();
	c_wallet_mock &wl = dynamic_cast<c_wallet_mock&>(*wallet);

	const std::string pk_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	t_hash_type pk;
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = sodium_hex2bin(pk.data(), pk.size(),
							pk_str.data(), pk_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl, get_main_pk())
	        .WillOnce(Return(pk));

	c_mediator_mock mediator_mock;
	auto wl_module = std::make_unique<c_wallet_module>(mediator_mock, std::move(wallet));
	const auto pk_test = wl_module->get_main_pk();
	EXPECT_EQ(pk_test, pk);
}

TEST(wallet_module, sign_tx_by_main_identity) {
	std::unique_ptr<c_wallet> wallet = std::make_unique<c_wallet_mock>();
	c_wallet_mock &wl = dynamic_cast<c_wallet_mock&>(*wallet);

	c_transaction tx;
	tx.m_vin.resize(1);
	tx.m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	int ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_txid = txid;
	tx.m_type = t_transactiontype::authorize_organizer;
	const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
						tx_vin_pk_str.data(), tx_vin_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_vin.at(0).m_sign.fill(0x00);
	tx.m_vin.at(0).m_txid.fill(0x00);
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	t_signature_type sign;
	const std::string sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(sign.data(), sign.size(),
						sign_str.data(), sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl, sign_tx_by_main_identity(tx))
	        .WillOnce(Return(sign));

	c_mediator_mock mediator_mock;
	auto wl_module = std::make_unique<c_wallet_module>(mediator_mock, std::move(wallet));
	const auto sign_test = wl_module->sign_tx_by_main_identity(tx);
	EXPECT_EQ(sign_test, sign);
}

TEST(wallet_module, sign_message_using_main_pk) {
	std::unique_ptr<c_wallet> wallet = std::make_unique<c_wallet_mock>();
	c_wallet_mock &wl = dynamic_cast<c_wallet_mock&>(*wallet);

	std::string_view message={"TEST"};

	t_signature_type sign;
	const std::string sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
	const auto ret = sodium_hex2bin(sign.data(), sign.size(),
									sign_str.data(), sign_str.size(),
									nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl, sign_message(message))
	        .WillOnce(Return(sign));

	c_mediator_mock mediator_mock;
	auto wl_module = std::make_unique<c_wallet_module>(mediator_mock, std::move(wallet));
	const auto sign_test = wl_module->sign_message_using_main_pk(message);
	EXPECT_EQ(sign_test, sign);
}

TEST(wallet_module, get_words_of_seed) {
	std::unique_ptr<c_wallet> wallet = std::make_unique<c_wallet_mock>();
	c_wallet_mock &wl = dynamic_cast<c_wallet_mock&>(*wallet);

	std::array<std::string, 12> words = {"style","coil","alcohol","horn","industry","blind",
	                                     "nerve","blind","final","pigeon","off","brown"};

	using ::testing::Return;
	EXPECT_CALL(wl, get_words_of_seed())
	        .WillOnce(Return(words));

	c_mediator_mock mediator_mock;
	auto wl_module = std::make_unique<c_wallet_module>(mediator_mock, std::move(wallet));
	const auto words_test = wl_module->get_words_of_seed();
	EXPECT_EQ(words_test, words);
}

TEST(wallet_module, generate_seed_from_words) {
	std::unique_ptr<c_wallet> wallet = std::make_unique<c_wallet_mock>();
	c_wallet_mock &wl = dynamic_cast<c_wallet_mock&>(*wallet);

	const std::array<std::string, 12> seed_words = {"style","coil","alcohol","horn","industry","blind",
	                                                "nerve","blind","final","pigeon","off","brown"};
	const std::filesystem::path file_path = ".";
	EXPECT_CALL(wl, generate_seed_from_words(seed_words))
	        .WillOnce(
	            [&seed_words](const std::array<std::string, 12> & seed_words_tmp){
		return seed_words == seed_words_tmp;
	});

	c_mediator_mock mediator_mock;
	auto wl_module = std::make_unique<c_wallet_module>(mediator_mock, std::move(wallet));
	wl_module->generate_seed_from_words(seed_words);
}
