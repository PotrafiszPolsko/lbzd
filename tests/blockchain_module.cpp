#include <gtest/gtest.h>
#include <queue>
#include "../src/blockchain_module.hpp"
#include "../src/blockchain_module_builder.hpp"
#include "mediator_mock.hpp"
#include "../src/serialization_utils.hpp"
#include "blockchain_mock.hpp"
#include "utxo_mock.hpp"
#include "../src/txid_generate.hpp"

TEST(blockchain_module, get_block_at_hash) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	c_block block;
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_actual_hash = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_tx_hash = all_tx_hash;
	block.m_header.m_block_time = 1679079676;
	t_hash_type parent_hash;
	const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_parent_hash = parent_hash;
	block.m_header.m_version = 0;
	std::vector<c_transaction> txs;
	txs.resize(1);
	txs.at(0).m_vin.resize(1);
	txs.at(0).m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=txs.at(0).m_txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txs.at(0).m_txid.data(), txs.at(0).m_txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_type = t_transactiontype::authorize_organizer;
	const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
						tx_vin_pk_str.data(), tx_vin_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
						tx_vin_sign_str.data(), tx_vin_sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_vin.at(0).m_txid.fill(0x00);
	txs.at(0).m_vout.at(0).m_amount = 0;
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc, get_block_at_hash(actual_hash))
	        .WillOnce(Return(block));
	
	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto block_test = bc_module->get_block_at_hash(actual_hash);
	EXPECT_EQ(block, block_test);
}

TEST(blockchain_module, get_block_at_hash_proto) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	c_block block;
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_actual_hash = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_tx_hash = all_tx_hash;
	block.m_header.m_block_time = 1679079676;
	t_hash_type parent_hash;
	const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_parent_hash = parent_hash;
	block.m_header.m_version = 0;
	std::vector<c_transaction> txs;
	txs.resize(1);
	txs.at(0).m_vin.resize(1);
	txs.at(0).m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=txs.at(0).m_txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txs.at(0).m_txid.data(), txs.at(0).m_txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_type = t_transactiontype::authorize_organizer;
	const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
						tx_vin_pk_str.data(), tx_vin_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
						tx_vin_sign_str.data(), tx_vin_sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
	if(tx_vin_txid_str.size()!=txs.at(0).m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_txid.data(), txs.at(0).m_vin.at(0).m_txid.size(),
						tx_vin_txid_str.data(), tx_vin_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_vout.at(0).m_amount = 0;
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;
	const auto block_proto = block_to_protobuf(block);

	using ::testing::Return;
	EXPECT_CALL(bc, get_block_at_hash_proto(actual_hash))
	        .WillOnce(Return(block_proto));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto block_test_proto = bc_module->get_block_at_hash_proto(actual_hash);
	const auto block_tests_from_proto = block_from_protobuf(block_proto);
	EXPECT_EQ(block, block_tests_from_proto);
}

TEST(blockchain_module, get_block_by_txid) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	c_block block;
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_actual_hash = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_tx_hash = all_tx_hash;
	block.m_header.m_block_time = 1679079676;
	t_hash_type parent_hash;
	const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_parent_hash = parent_hash;
	block.m_header.m_version = 0;
	std::vector<c_transaction> txs;
	txs.resize(1);
	txs.at(0).m_vin.resize(1);
	txs.at(0).m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
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
	txs.at(0).m_txid = txid;
	txs.at(0).m_type = t_transactiontype::authorize_organizer;
	const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
						tx_vin_pk_str.data(), tx_vin_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
						tx_vin_sign_str.data(), tx_vin_sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_vin.at(0).m_txid.fill(0x00);
	txs.at(0).m_vout.at(0).m_amount = 0;
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc, get_block_by_txid(txid))
	        .WillOnce(Return(block));
	
	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto block_test = bc_module->get_block_by_txid(txid);
	EXPECT_EQ(block, block_test);
}

TEST(blockchain_module, get_last_block_time) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	c_block block;
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_actual_hash = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_tx_hash = all_tx_hash;
	block.m_header.m_block_time = 1679079676;
	t_hash_type parent_hash;
	const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_parent_hash = parent_hash;
	block.m_header.m_version = 0;
	std::vector<c_transaction> txs;
	txs.resize(1);
	txs.at(0).m_vin.resize(1);
	txs.at(0).m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
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
	txs.at(0).m_txid = txid;
	txs.at(0).m_type = t_transactiontype::authorize_organizer;
	const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
						tx_vin_pk_str.data(), tx_vin_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
						tx_vin_sign_str.data(), tx_vin_sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_vin.at(0).m_txid.fill(0x00);
	txs.at(0).m_vout.at(0).m_amount = 0;
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	const auto block_time = block.m_header.m_block_time;

	using ::testing::Return;
	EXPECT_CALL(bc, get_last_block())
	        .WillOnce(Return(block));
	
	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto block_time_test = bc_module->get_last_block_time();
	EXPECT_EQ(block_time, block_time_test);
}

TEST(blockchain_module, get_number_of_transactions) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	const size_t number_of_txs = 12543;

	using ::testing::Return;
	EXPECT_CALL(bc, get_number_of_transactions())
	        .WillOnce(Return(number_of_txs));
	
	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto number_of_txs_test = bc_module->get_number_of_transactions();
	EXPECT_EQ(number_of_txs, number_of_txs_test);
}

TEST(blockchain_module, get_last_5_blocks) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	std::vector<c_block_record> blocks_record;
	{
		c_block_record block_record;
		const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079676;
		const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "xxxxx";
		block_record.m_height = 39;
		block_record.m_number_of_transactions = 900;
		block_record.m_position_in_file = 5;
		block_record.m_size_of_binary_data = 100;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "aa677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "aa7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079686;
		const std::string parent_hash_str = "aa31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "yyyyyy";
		block_record.m_height = 38;
		block_record.m_number_of_transactions = 1900;
		block_record.m_position_in_file = 50;
		block_record.m_size_of_binary_data = 1000;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "bb677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "bb7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "bbeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079696;
		const std::string parent_hash_str = "bb31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "zzzzz";
		block_record.m_height = 37;
		block_record.m_number_of_transactions = 200;
		block_record.m_position_in_file = 100;
		block_record.m_size_of_binary_data = 200;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "cc677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "cc7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "cceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079700;
		const std::string parent_hash_str = "cc31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "tttttttt";
		block_record.m_height = 36;
		block_record.m_number_of_transactions = 2304;
		block_record.m_position_in_file = 1;
		block_record.m_size_of_binary_data = 3400;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "dd677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "dd7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "ddeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079710;
		const std::string parent_hash_str = "dd31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "wwwwww";
		block_record.m_height = 35;
		block_record.m_number_of_transactions = 400;
		block_record.m_position_in_file = 7;
		block_record.m_size_of_binary_data = 700;
		blocks_record.push_back(block_record);
	}

	using ::testing::Return;
	EXPECT_CALL(bc, get_last_5_blocks())
	        .WillOnce(Return(blocks_record));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto last_5_blocks = bc_module->get_last_5_blocks();
	EXPECT_EQ(blocks_record, last_5_blocks);
}

TEST(blockchain_module, get_last_5_transactions) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	std::vector<c_transaction> txs;
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "aa4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "aa07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "aaaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "aaa3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "bb4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "bbeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "bb07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "bbaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "bba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "cc4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "cceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "cc07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ccaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "cca3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "dd4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "ddeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "dd07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ddaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}

	using ::testing::Return;
	EXPECT_CALL(bc, get_last_5_transactions())
	        .WillOnce(Return(txs));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto last_5_transactions = bc_module->get_last_5_transactions();
	EXPECT_EQ(txs, last_5_transactions);
}

TEST(blockchain_module, get_sorted_blocks) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	std::vector<c_block_record> blocks_record;
	{
		c_block_record block_record;
		const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079676;
		const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "xxxxx";
		block_record.m_height = 39;
		block_record.m_number_of_transactions = 900;
		block_record.m_position_in_file = 5;
		block_record.m_size_of_binary_data = 100;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "aa677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "aa7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079686;
		const std::string parent_hash_str = "aa31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "yyyyyy";
		block_record.m_height = 38;
		block_record.m_number_of_transactions = 1900;
		block_record.m_position_in_file = 50;
		block_record.m_size_of_binary_data = 1000;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "bb677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "bb7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "bbeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079696;
		const std::string parent_hash_str = "bb31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "zzzzz";
		block_record.m_height = 37;
		block_record.m_number_of_transactions = 200;
		block_record.m_position_in_file = 100;
		block_record.m_size_of_binary_data = 200;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "cc677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "cc7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "cceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079700;
		const std::string parent_hash_str = "cc31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "tttttttt";
		block_record.m_height = 36;
		block_record.m_number_of_transactions = 2304;
		block_record.m_position_in_file = 1;
		block_record.m_size_of_binary_data = 3400;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "dd677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "dd7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "ddeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079710;
		const std::string parent_hash_str = "dd31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "wwwwww";
		block_record.m_height = 35;
		block_record.m_number_of_transactions = 400;
		block_record.m_position_in_file = 7;
		block_record.m_size_of_binary_data = 700;
		blocks_record.push_back(block_record);
	}

	const size_t amount_of_blocks = 5;

	using ::testing::Return;
	EXPECT_CALL(bc, get_sorted_blocks(amount_of_blocks))
	        .WillOnce(Return(blocks_record));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto sorted_blocks = bc_module->get_sorted_blocks(amount_of_blocks);
	EXPECT_EQ(blocks_record, sorted_blocks);
}

TEST(blockchain_module, get_sorted_blocks_per_page) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	std::vector<c_block_record> blocks_record;
	{
		c_block_record block_record;
		const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079676;
		const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "xxxxx";
		block_record.m_height = 39;
		block_record.m_number_of_transactions = 900;
		block_record.m_position_in_file = 5;
		block_record.m_size_of_binary_data = 100;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "aa677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "aa7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079686;
		const std::string parent_hash_str = "aa31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "yyyyyy";
		block_record.m_height = 38;
		block_record.m_number_of_transactions = 1900;
		block_record.m_position_in_file = 50;
		block_record.m_size_of_binary_data = 1000;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "bb677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "bb7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "bbeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079696;
		const std::string parent_hash_str = "bb31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "zzzzz";
		block_record.m_height = 37;
		block_record.m_number_of_transactions = 200;
		block_record.m_position_in_file = 100;
		block_record.m_size_of_binary_data = 200;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "cc677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "cc7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "cceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079700;
		const std::string parent_hash_str = "cc31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "tttttttt";
		block_record.m_height = 36;
		block_record.m_number_of_transactions = 2304;
		block_record.m_position_in_file = 1;
		block_record.m_size_of_binary_data = 3400;
		blocks_record.push_back(block_record);
	}
	{
		c_block_record block_record;
		const std::string actual_hash_str = "dd677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
		if(actual_hash_str.size()!=block_record.m_header.m_actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
		int ret = 1;
		ret = sodium_hex2bin(block_record.m_header.m_actual_hash.data(), block_record.m_header.m_actual_hash.size(),
							actual_hash_str.data(), actual_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_all_signatures.resize(1);
		const std::string all_signatures_str = "dd7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
		if(all_signatures_str.size()!=block_record.m_header.m_all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
		ret = sodium_hex2bin(block_record.m_header.m_all_signatures.at(0).data(), block_record.m_header.m_all_signatures.at(0).size(),
							all_signatures_str.data(), all_signatures_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string all_tx_hash_str = "ddeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(all_tx_hash_str.size()!=block_record.m_header.m_all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
		ret = sodium_hex2bin(block_record.m_header.m_all_tx_hash.data(), block_record.m_header.m_all_tx_hash.size(),
							all_tx_hash_str.data(), all_tx_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_block_time = 1679079710;
		const std::string parent_hash_str = "dd31afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
		if(parent_hash_str.size()!=block_record.m_header.m_parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
		ret = sodium_hex2bin(block_record.m_header.m_parent_hash.data(), block_record.m_header.m_parent_hash.size(),
							parent_hash_str.data(), parent_hash_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		block_record.m_header.m_version = 0;
		block_record.m_file_contains_block = "wwwwww";
		block_record.m_height = 35;
		block_record.m_number_of_transactions = 400;
		block_record.m_position_in_file = 7;
		block_record.m_size_of_binary_data = 700;
		blocks_record.push_back(block_record);
	}

	const size_t current_height = 5;
	const auto blocks_per_page = std::make_pair(blocks_record, current_height);
	const size_t offset = 1;

	using ::testing::Return;
	EXPECT_CALL(bc, get_sorted_blocks_per_page(offset))
	        .WillOnce(Return(blocks_per_page));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto sorted_blocks_per_page = bc_module->get_sorted_blocks_per_page(offset);
	EXPECT_EQ(blocks_per_page, sorted_blocks_per_page);
	EXPECT_EQ(current_height, sorted_blocks_per_page.second);
}

TEST(blockchain_module, get_latest_transactions) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	std::vector<c_transaction> txs;
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "aa4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "aa07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "aaaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "aaa3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "bb4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "bbeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "bb07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "bbaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "bba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "cc4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "cceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "cc07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ccaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "cca3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "dd4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "ddeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "dd07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ddaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}

	const size_t amount_of_txs = 5;
	using ::testing::Return;
	EXPECT_CALL(bc, get_latest_transactions(amount_of_txs))
	        .WillOnce(Return(txs));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto latest_transactions = bc_module->get_latest_transactions(amount_of_txs);
	EXPECT_EQ(txs, latest_transactions);
}

TEST(blockchain_module, get_txs_per_page) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	std::vector<c_transaction> txs;
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "aa4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "aa07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "aaaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "aaa3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "bb4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "bbeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "bb07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "bbaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "bba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "cc4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "cceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "cc07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ccaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "cca3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "dd4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "ddeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "dd07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ddaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	const size_t amount_txs = 5;
	const auto txs_per_page = std::make_pair(txs, amount_txs);
	const size_t offset = 1;

	using ::testing::Return;
	EXPECT_CALL(bc, get_txs_per_page(offset))
	        .WillOnce(Return(txs_per_page));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto transactions_per_page = bc_module->get_txs_per_page(offset);
	EXPECT_EQ(txs, transactions_per_page.first);
	EXPECT_EQ(amount_txs, transactions_per_page.second);
}

TEST(blockchain_module, get_txs_from_block_per_page) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	std::vector<c_transaction> txs;
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "aa4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "aa07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "aaaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "aaa3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "bb4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "bbeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "bb07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "bbaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "bba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "cc4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "cceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "cc07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ccaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "cca3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	{
		c_transaction tx;
		tx.m_vin.resize(1);
		tx.m_vout.resize(1);
		const std::string tx_allmetadata_str = "dd4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
		tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
		if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
		int ret = 1;
		ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
							tx_allmetadata_str.data(), tx_allmetadata_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_txid_str = "ddeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
		if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
		ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
							tx_txid_str.data(), tx_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_type = t_transactiontype::authorize_voter;
		const std::string tx_vin_pk_str = "dd07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
		if(tx_vin_pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
							tx_vin_pk_str.data(), tx_vin_pk_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_sign_str = "ddaa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
		if(tx_vin_sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
							tx_vin_sign_str.data(), tx_vin_sign_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
		if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
		ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
							tx_vin_txid_str.data(), tx_vin_txid_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		tx.m_vout.at(0).m_amount = 0;
		const std::string tx_vout_pkh_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	std::sort(txs.begin(), txs.end(),
	[](const c_transaction & tx_1, const c_transaction & tx_2){return tx_1.m_txid < tx_2.m_txid;});
	const std::string block_id_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	t_hash_type block_id;
	if(block_id_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad block_id size");
	const auto ret = sodium_hex2bin(block_id.data(), block_id.size(),
							block_id_str.data(), block_id_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const size_t amount_txs = 5;
	const auto txs_per_page = std::make_pair(txs, amount_txs);
	const size_t offset = 1;

	using ::testing::Return;
	EXPECT_CALL(bc, get_txs_from_block_per_page(offset, block_id))
	        .WillOnce(Return(txs_per_page));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto transactions_from_block_per_page = bc_module->get_txs_from_block_per_page(offset, block_id);
	EXPECT_EQ(txs, transactions_from_block_per_page.first);
	EXPECT_EQ(amount_txs, transactions_from_block_per_page.second);
}

TEST(blockchain_module, get_block_id_by_txid) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(bc, get_block_id_by_txid(txid))
	        .WillOnce(Return(actual_hash));
	
	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto block_id = bc_module->get_block_id_by_txid(txid);
	EXPECT_EQ(actual_hash, block_id);
}

TEST(blockchain_module, get_merkle_branch) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	int ret = 1;
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type hash_merkle;
	const std::string hash_merkle_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(hash_merkle_str.size()!=hash_merkle.size()*2) throw std::invalid_argument("Bad hash_merkle size");
	ret = sodium_hex2bin(hash_merkle.data(), hash_merkle.size(),
						hash_merkle_str.data(), hash_merkle_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type hash_merkle_root;
	const std::string hash_merkle_root_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(hash_merkle_root_str.size()!=hash_merkle_root.size()*2) throw std::invalid_argument("Bad hash_merkle_root size");
	ret = sodium_hex2bin(hash_merkle_root.data(), hash_merkle_root.size(),
						hash_merkle_root_str.data(), hash_merkle_root_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<t_hash_type> merkle_branch;
	merkle_branch.push_back(hash_merkle_root);
	merkle_branch.push_back(hash_merkle);

	using ::testing::Return;
	EXPECT_CALL(bc, get_merkle_branch(txid))
	        .WillOnce(Return(merkle_branch));
	
	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto merkle_branch_test = bc_module->get_merkle_branch(txid);
	EXPECT_EQ(merkle_branch, merkle_branch_test);
}

TEST(blockchain_module, get_block_signatures_and_pk_miners_per_page) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	c_block block;
	t_hash_type block_id;
	const std::string block_id_str = "570530f61eaa55c9b63b05b6b410c23c9ef52af1f6108e1e8021986eab1d79af";
	if(block_id_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad block_id size");
	int ret = 1;
	ret = sodium_hex2bin(block_id.data(), block_id.size(),
						block_id_str.data(), block_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");	
	block.m_header.m_actual_hash = block_id;
	t_signature_type signature;
	const std::string signature_str = "439a6c99a9ca67487e8f2840fb716d7d72bb2d86f533c218c975e6a5526c795523801da2c9a3b272fc4ad11c3f600ed75594e60c4cd0ab02196de90f62faf00f";
	if(signature_str.size()!=signature.size()*2) throw std::invalid_argument("Bad signature size");
	ret = sodium_hex2bin(signature.data(), signature.size(),
						signature_str.data(), signature_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<t_signature_type> all_signatures;
	all_signatures.push_back(signature);
	block.m_header.m_all_signatures = all_signatures;
	size_t offset = 1;

	t_public_key_type miner_pk;
	const std::string miner_pk_str = "f1a8d7ca6a473db7c66ceb79d58b54b00526d129c46bf3bcb1ba745b56dea3a6";
	if(miner_pk_str.size()!=miner_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(miner_pk.data(), miner_pk.size(),
						miner_pk_str.data(), miner_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	std::vector<t_public_key_type> miners_pk;
	miners_pk.push_back(miner_pk);

	const auto sign_and_pk = std::make_pair(all_signatures.at(0), miner_pk) ;
	std::vector<std::pair<t_signature_type, t_public_key_type>> vec_signs_and_pks;
	vec_signs_and_pks.push_back(sign_and_pk);
	auto signs_and_pks = std::make_pair(vec_signs_and_pks, all_signatures.size());

	using ::testing::Return;
	EXPECT_CALL(bc, get_block_at_hash(block_id))
	        .WillRepeatedly(Return(block));

	EXPECT_CALL(ut, get_all_miners_public_keys())
	        .WillRepeatedly(Return(miners_pk));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	auto signs_and_pks_per_page = bc_module->get_block_signatures_and_pk_miners_per_page(offset, block_id);
	EXPECT_EQ(signs_and_pks, signs_and_pks_per_page);

	for(size_t i=0; i<4; i++) {
		miners_pk.push_back(miner_pk);
		all_signatures.push_back(signature);
		vec_signs_and_pks.push_back(sign_and_pk);
	}
	block.m_header.m_all_signatures = all_signatures;
	
	EXPECT_CALL(bc, get_block_at_hash(block_id))
	        .WillRepeatedly(Return(block));

	EXPECT_CALL(ut, get_all_miners_public_keys())
	        .WillRepeatedly(Return(miners_pk));

	signs_and_pks = std::make_pair(vec_signs_and_pks, all_signatures.size());

	signs_and_pks_per_page = bc_module->get_block_signatures_and_pk_miners_per_page(offset, block_id);
	EXPECT_EQ(signs_and_pks, signs_and_pks_per_page);

	miners_pk.push_back(miner_pk);
	all_signatures.push_back(signature);

	block.m_header.m_all_signatures = all_signatures;

	EXPECT_CALL(bc, get_block_at_hash(block_id))
	        .WillRepeatedly(Return(block));

	EXPECT_CALL(ut, get_all_miners_public_keys())
	        .WillRepeatedly(Return(miners_pk));

	vec_signs_and_pks.clear();
	vec_signs_and_pks.push_back(sign_and_pk);
	signs_and_pks = std::make_pair(vec_signs_and_pks, all_signatures.size());
	offset = 2;

	signs_and_pks_per_page = bc_module->get_block_signatures_and_pk_miners_per_page(offset, block_id);
	EXPECT_EQ(signs_and_pks, signs_and_pks_per_page);
}

TEST(blockchain_module, get_votings_per_page) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_hash_type voting_id;
	const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
						voting_id_str.data(), voting_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	const uint32_t voting_end_time = 1679189050;
	const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";

	auto voting = std::make_pair(voting_id, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(voting);

	using ::testing::Return;
	EXPECT_CALL(ut, get_all_votings())
	        .WillRepeatedly(Return(votings));

	size_t number_votings = votings.size();
	size_t offset = 1;
	auto votings_and_number_votings = std::make_pair(votings, number_votings);

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	auto votings_and_number_votings_test = bc_module->get_votings_per_page(offset);
	EXPECT_EQ(votings_and_number_votings, votings_and_number_votings_test);

	t_hash_type voting_id_1;
	const std::string voting_id_1_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_1_str.size()!=voting_id_1.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_1.data(), voting_id_1.size(),
						voting_id_1_str.data(), voting_id_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_1, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_2;
	const std::string voting_id_2_str = "bbefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_2_str.size()!=voting_id_2.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_2.data(), voting_id_2.size(),
						voting_id_2_str.data(), voting_id_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_2, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_3;
	const std::string voting_id_3_str = "ccefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_3_str.size()!=voting_id_3.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_3.data(), voting_id_3.size(),
						voting_id_3_str.data(), voting_id_3_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_3, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_4;
	const std::string voting_id_4_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_4_str.size()!=voting_id_4.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_4.data(), voting_id_4.size(),
						voting_id_4_str.data(), voting_id_4_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_4, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_5;
	const std::string voting_id_5_str = "eeefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_5_str.size()!=voting_id_5.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_5.data(), voting_id_5.size(),
						voting_id_5_str.data(), voting_id_5_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_5, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_6;
	const std::string voting_id_6_str = "ffefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_6_str.size()!=voting_id_6.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_6.data(), voting_id_6.size(),
						voting_id_6_str.data(), voting_id_6_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_6, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_7;
	const std::string voting_id_7_str = "aaaad000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_7_str.size()!=voting_id_7.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_7.data(), voting_id_7.size(),
						voting_id_7_str.data(), voting_id_7_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_7, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_8;
	const std::string voting_id_8_str = "aabbd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_8_str.size()!=voting_id_8.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_8.data(), voting_id_8.size(),
						voting_id_8_str.data(), voting_id_8_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_8, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_9;
	const std::string voting_id_9_str = "aaccd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_9_str.size()!=voting_id_9.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_9.data(), voting_id_9.size(),
						voting_id_9_str.data(), voting_id_9_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_9, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_10;
	const std::string voting_id_10_str = "ffffd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_10_str.size()!=voting_id_10.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_10.data(), voting_id_10.size(),
						voting_id_10_str.data(), voting_id_10_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_10, voting_metadata);
	votings.push_back(voting);

	EXPECT_CALL(ut, get_all_votings())
	        .WillRepeatedly(Return(votings));

	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2) {
		if(voting_1.first < voting_2.first) return true;
		else return false;
	});
	number_votings = votings.size();

	offset = 2;
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_for_offset_2;
	votings_for_offset_2.push_back(votings.at(10));
	votings_and_number_votings = std::make_pair(votings_for_offset_2, number_votings);

	votings_and_number_votings_test = bc_module->get_votings_per_page(offset);
	EXPECT_EQ(votings_and_number_votings, votings_and_number_votings_test);
	offset = 1;
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_for_offset_1;
	std::copy_n(votings.cbegin(), n_rpcparams::number_of_votings_per_page, std::back_inserter(votings_for_offset_1));
	votings_and_number_votings = std::make_pair(votings_for_offset_1, number_votings);
	votings_and_number_votings_test = bc_module->get_votings_per_page(offset);
	EXPECT_EQ(votings_and_number_votings, votings_and_number_votings_test);
}

TEST(blockchain_module, get_latest_votings) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_hash_type voting_id_1;
	const std::string voting_id_1_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_1_str.size()!=voting_id_1.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id_1.data(), voting_id_1.size(),
						voting_id_1_str.data(), voting_id_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	const uint32_t voting_end_time = 1679189050;
	const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";

	auto voting = std::make_pair(voting_id_1, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(voting);
	t_hash_type voting_id_2;
	const std::string voting_id_2_str = "ffffd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_2_str.size()!=voting_id_2.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_2.data(), voting_id_2.size(),
						voting_id_2_str.data(), voting_id_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_2, voting_metadata);
	votings.push_back(voting);

	using ::testing::Return;
	EXPECT_CALL(ut, get_all_votings())
	        .WillRepeatedly(Return(votings));

	size_t amount_votings = votings.size();
	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2) {
		if(voting_1.first < voting_2.first) return true;
		else return false;
	});

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	auto votings_test = bc_module->get_latest_votings(amount_votings);
	EXPECT_EQ(votings, votings_test);

	amount_votings = votings.size()+3;
	votings_test = bc_module->get_latest_votings(amount_votings);
	EXPECT_EQ(votings, votings_test);

	amount_votings = votings.size()-1;
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_tmp;
	votings_tmp.push_back(votings.at(0));
	votings_test = bc_module->get_latest_votings(amount_votings);
	EXPECT_EQ(votings_tmp, votings_test);
}

TEST(blockchain_module, get_all_votings_by_name_or_voting_id_with_number_votings) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_hash_type voting_id;
	const std::string voting_id_str = "aaaaaa00c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
						voting_id_str.data(), voting_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	const uint32_t voting_end_time = 1679189050;
	const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";

	auto voting = std::make_pair(voting_id, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(voting);

	t_hash_type voting_id_1;
	const std::string voting_id_1_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_1_str.size()!=voting_id_1.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_1.data(), voting_id_1.size(),
						voting_id_1_str.data(), voting_id_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_1, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_2;
	const std::string voting_id_2_str = "bbefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_2_str.size()!=voting_id_2.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_2.data(), voting_id_2.size(),
						voting_id_2_str.data(), voting_id_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_2, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_3;
	const std::string voting_id_3_str = "ccefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_3_str.size()!=voting_id_3.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_3.data(), voting_id_3.size(),
						voting_id_3_str.data(), voting_id_3_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_3, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_4;
	const std::string voting_id_4_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_4_str.size()!=voting_id_4.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_4.data(), voting_id_4.size(),
						voting_id_4_str.data(), voting_id_4_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_4, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_5;
	const std::string voting_id_5_str = "eeefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_5_str.size()!=voting_id_5.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_5.data(), voting_id_5.size(),
						voting_id_5_str.data(), voting_id_5_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_5, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_6;
	const std::string voting_id_6_str = "ffefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_6_str.size()!=voting_id_6.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_6.data(), voting_id_6.size(),
						voting_id_6_str.data(), voting_id_6_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_6, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_7;
	const std::string voting_id_7_str = "aaaad000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_7_str.size()!=voting_id_7.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_7.data(), voting_id_7.size(),
						voting_id_7_str.data(), voting_id_7_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_7, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_8;
	const std::string voting_id_8_str = "aabbd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_8_str.size()!=voting_id_8.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_8.data(), voting_id_8.size(),
						voting_id_8_str.data(), voting_id_8_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_8, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_9;
	const std::string voting_id_9_str = "aaccd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_9_str.size()!=voting_id_9.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_9.data(), voting_id_9.size(),
						voting_id_9_str.data(), voting_id_9_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_9, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_10;
	const std::string voting_id_10_str = "ffffd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_10_str.size()!=voting_id_10.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_10.data(), voting_id_10.size(),
						voting_id_10_str.data(), voting_id_10_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_10, voting_metadata);
	votings.push_back(voting);

	using ::testing::Return;
	EXPECT_CALL(ut, get_all_votings())
	        .WillRepeatedly(Return(votings));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));

	const size_t number_votings = votings.size();
	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2) {
		if(voting_1.first < voting_2.first) return true;
		else return false;
	});
	size_t offset = 2;
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_for_offset_2;
	votings_for_offset_2.push_back(votings.at(10));
	auto votings_and_number_votings = std::make_pair(votings_for_offset_2, number_votings);
	auto votings_and_number_votings_test = bc_module->get_all_votings_by_name_or_voting_id_with_number_votings(offset, voting_metadata.m_name);
	EXPECT_EQ(votings_and_number_votings, votings_and_number_votings_test);

	EXPECT_CALL(ut, get_voting_metadata_by_voting_id(voting_id_10))
	        .WillRepeatedly(Return(voting_metadata));

	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_for_voting_id;
	votings_for_voting_id.push_back(votings.at(10));
	votings_and_number_votings = std::make_pair(votings_for_voting_id, votings_for_voting_id.size());
	offset = 1;
	votings_and_number_votings_test = bc_module->get_all_votings_by_name_or_voting_id_with_number_votings(offset, voting_id_10_str);
	EXPECT_EQ(votings_and_number_votings, votings_and_number_votings_test);

	votings.erase(votings.end()-1);
	votings_and_number_votings = std::make_pair(votings, number_votings);
	votings_and_number_votings_test = bc_module->get_all_votings_by_name_or_voting_id_with_number_votings(offset, voting_metadata.m_name);
	EXPECT_EQ(votings_and_number_votings, votings_and_number_votings_test);

	t_hash_type voting_name;
	const std::string voting_name_str = "0000000000000000000000000000000000000000000000000000000000000000";
	if(voting_name_str.size()!=voting_name.size()*2) throw std::invalid_argument("Bad voting_name size");
	ret = sodium_hex2bin(voting_name.data(), voting_name.size(),
						voting_name_str.data(), voting_name_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_voting_metadata voting_metadata_empty;
	voting_metadata_empty.m_start_timepoint = 0;
	voting_metadata_empty.m_number_of_blocks_to_the_end = 0;
	voting_metadata_empty.m_name.clear();
	voting_metadata_empty.m_voting_type = 0;
	voting_metadata_empty.m_authorization_level = 0;
	voting_metadata_empty.m_number_of_choice = 0;
	voting_metadata_empty.m_options.clear();
	voting_metadata_empty.m_question.clear();

	EXPECT_CALL(ut, get_voting_metadata_by_voting_id(voting_name))
	        .WillRepeatedly(Return(voting_metadata_empty));

	EXPECT_THROW(bc_module->get_all_votings_by_name_or_voting_id_with_number_votings(offset, voting_name_str), std::invalid_argument);
}

TEST(blockchain_module, finished_or_active_votings) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";

	t_hash_type voting_id_1;
	const std::string voting_id_1_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_1_str.size()!=voting_id_1.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id_1.data(), voting_id_1.size(),
						voting_id_1_str.data(), voting_id_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	auto voting = std::make_pair(voting_id_1, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_finished;
	votings_finished.push_back(voting);

	using ::testing::Return;
	EXPECT_CALL(ut, get_all_finished_votings())
	        .WillRepeatedly(Return(votings_finished));

	std::vector<std::pair<t_hash_type, bool>> votings_finished_or_active;
	const auto finished_voting = std::make_pair(votings_finished.at(0).first, true);
	votings_finished_or_active.push_back(finished_voting);

	t_hash_type voting_id_2;
	const std::string voting_id_2_str = "bbefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_2_str.size()!=voting_id_2.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_2.data(), voting_id_2.size(),
						voting_id_2_str.data(), voting_id_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting_metadata.m_start_timepoint = 1679180000;
	voting_end_time = 1679185000;
	voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting = std::make_pair(voting_id_2, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_active;
	votings_active.push_back(voting);

	EXPECT_CALL(ut, get_all_active_votings())
	        .WillRepeatedly(Return(votings_active));

	const auto active_voting = std::make_pair(votings_active.at(0).first, false);
	votings_finished_or_active.push_back(active_voting);

	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(votings_finished.at(0));
	votings.push_back(votings_active.at(0));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	auto votings_finished_or_active_test = bc_module->finished_or_active_votings(votings);
	EXPECT_EQ(votings_finished_or_active, votings_finished_or_active_test);
}

TEST(blockchain_module, get_waiting_votings_ids) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";

	t_hash_type voting_id_1;
	const std::string voting_id_1_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_1_str.size()!=voting_id_1.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id_1.data(), voting_id_1.size(),
						voting_id_1_str.data(), voting_id_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	auto voting = std::make_pair(voting_id_1, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(voting);

	using ::testing::Return;
	EXPECT_CALL(ut, get_all_waiting_votings())
	        .WillOnce(Return(votings));

	std::vector<t_hash_type> votings_ids;
	votings_ids.push_back(votings.at(0).first);

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto votings_ids_test = bc_module->get_waiting_votings_ids(votings);
	EXPECT_EQ(votings_ids, votings_ids_test);
}

TEST(blockchain_module, get_votings_results_from_specific_votes) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";
	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	
	c_transaction tx_create_voting;
	tx_create_voting.m_type = t_transactiontype::create_voting;
	{
		// add question
		const auto question_metadata_value = get_metadata_variable_length_field("QS", voting_metadata.m_question);
		std::copy(question_metadata_value.cbegin(), question_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add voting options
		for (const auto & option : voting_metadata.m_options) {
			const auto option_metedata_value = get_metadata_variable_length_field("OP", option);
			std::copy(option_metedata_value.cbegin(), option_metedata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting name
		const auto voting_name_metadata_value = get_metadata_variable_length_field("VN", voting_metadata.m_name);
		std::copy(voting_name_metadata_value.cbegin(), voting_name_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add authorization level
		{
			const auto auth_level_as_array = get_array_byte(voting_metadata.m_authorization_level);
			const std::array<unsigned char, 2> al {'A', 'L'};
			std::copy(al.cbegin(), al.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(auth_level_as_array.cbegin(), auth_level_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of choice
		{
			const auto number_of_choice_as_array = get_array_byte(voting_metadata.m_number_of_choice);
			const std::array<unsigned char, 2> nc {'N', 'C'};
			std::copy(nc.cbegin(), nc.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_choice_as_array.cbegin(), number_of_choice_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of blocks to end
		{
			const auto number_of_blocks_as_array = get_array_byte(voting_metadata.m_number_of_blocks_to_the_end);
			const std::array<unsigned char, 2> be {'B', 'E'};
			std::copy(be.cbegin(), be.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_blocks_as_array.cbegin(), number_of_blocks_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add start timepoint
		{
			const auto unix_time_as_array = get_array_byte(voting_metadata.m_start_timepoint);
			const std::array<unsigned char, 2> st {'S', 'T'};
			std::copy(st.cbegin(), st.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(unix_time_as_array.cbegin(), unix_time_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting type - open or secret voting
		{
			const auto voting_type_array = get_array_byte(voting_metadata.m_voting_type);
			assert(voting_type_array.size()==1);
			const std::array<unsigned char, 2> vt {'V', 'T'};
			std::copy(vt.cbegin(), vt.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(voting_type_array.cbegin(), voting_type_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add nonce
		{
			std::array<unsigned char, 4> nonce;
			crypto_secure_random(&nonce[0], nonce.size());
			const std::array<unsigned char, 2> no {'N', 'O'};
			std::copy(no.cbegin(), no.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(nonce.cbegin(), nonce.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		{
			c_vin vin;
			vin.m_txid.fill(0x00);
			vin.m_sign.fill(0x00);
			vin.m_pk = organizer_pk;
			tx_create_voting.m_vin.push_back(std::move(vin));
		}
		{
			c_vout vout;
			vout.m_pkh.fill(0x00);
			vout.m_amount = 0;
			tx_create_voting.m_vout.push_back(std::move(vout));
		}
		tx_create_voting.m_txid = c_txid_generate::generate_txid(tx_create_voting);
	}

	using ::testing::Return;
	EXPECT_CALL(bc, get_transaction(tx_create_voting.m_txid))
	        .WillOnce(Return(tx_create_voting));

	const auto option_A = container_to_vector_of_uchars(voting_metadata.m_options.at(0));
	std::vector<unsigned char> hash_input_A(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_A.cbegin(), option_A.cend(), std::back_inserter(hash_input_A));
	const auto option_address_A = generate_hash(hash_input_A);
	const auto option_B = container_to_vector_of_uchars(voting_metadata.m_options.at(1));
	std::vector<unsigned char> hash_input_B(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_B.cbegin(), option_B.cend(), std::back_inserter(hash_input_B));
	const auto option_address_B = generate_hash(hash_input_B);

	const size_t amount_option_address_A = 45;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_A))
	        .WillRepeatedly(Return(amount_option_address_A));
	const size_t amount_option_address_B = 55;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_B))
	        .WillRepeatedly(Return(amount_option_address_B));

	std::unordered_map<std::string, uint32_t> result;
	result.emplace(voting_metadata.m_options.at(0), amount_option_address_A);
	result.emplace(voting_metadata.m_options.at(1), amount_option_address_B);
	const auto voting_result = std::make_pair(tx_create_voting.m_txid, result);

	const auto voting = std::make_pair(tx_create_voting.m_txid, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(voting);

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto votings_results = bc_module->get_votings_results_from_specific_votes(votings);
	auto it = votings_results.at(0).second.find("option A");
	EXPECT_EQ(amount_option_address_A, it->second);
	it = votings_results.at(0).second.find("option B");
	EXPECT_EQ(amount_option_address_B, it->second);
}

TEST(blockchain_module, get_number_of_all_voters) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	const size_t number_of_all_voters = 100;
	using ::testing::Return;
	EXPECT_CALL(ut, get_number_of_all_voters())
	        .WillOnce(Return(number_of_all_voters));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto number_voters = bc_module->get_number_of_all_voters();
	EXPECT_EQ(number_of_all_voters, number_voters);
}

TEST(blockchain_module, get_all_vote_transactions) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";
	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	
	c_transaction tx_create_voting;
	tx_create_voting.m_type = t_transactiontype::create_voting;
	{
		// add question
		const auto question_metadata_value = get_metadata_variable_length_field("QS", voting_metadata.m_question);
		std::copy(question_metadata_value.cbegin(), question_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add voting options
		for (const auto & option : voting_metadata.m_options) {
			const auto option_metedata_value = get_metadata_variable_length_field("OP", option);
			std::copy(option_metedata_value.cbegin(), option_metedata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting name
		const auto voting_name_metadata_value = get_metadata_variable_length_field("VN", voting_metadata.m_name);
		std::copy(voting_name_metadata_value.cbegin(), voting_name_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add authorization level
		{
			const auto auth_level_as_array = get_array_byte(voting_metadata.m_authorization_level);
			const std::array<unsigned char, 2> al {'A', 'L'};
			std::copy(al.cbegin(), al.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(auth_level_as_array.cbegin(), auth_level_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of choice
		{
			const auto number_of_choice_as_array = get_array_byte(voting_metadata.m_number_of_choice);
			const std::array<unsigned char, 2> nc {'N', 'C'};
			std::copy(nc.cbegin(), nc.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_choice_as_array.cbegin(), number_of_choice_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of blocks to end
		{
			const auto number_of_blocks_as_array = get_array_byte(voting_metadata.m_number_of_blocks_to_the_end);
			const std::array<unsigned char, 2> be {'B', 'E'};
			std::copy(be.cbegin(), be.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_blocks_as_array.cbegin(), number_of_blocks_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add start timepoint
		{
			const auto unix_time_as_array = get_array_byte(voting_metadata.m_start_timepoint);
			const std::array<unsigned char, 2> st {'S', 'T'};
			std::copy(st.cbegin(), st.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(unix_time_as_array.cbegin(), unix_time_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting type - open or secret voting
		{
			const auto voting_type_array = get_array_byte(voting_metadata.m_voting_type);
			assert(voting_type_array.size()==1);
			const std::array<unsigned char, 2> vt {'V', 'T'};
			std::copy(vt.cbegin(), vt.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(voting_type_array.cbegin(), voting_type_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add nonce
		{
			std::array<unsigned char, 4> nonce;
			crypto_secure_random(&nonce[0], nonce.size());
			const std::array<unsigned char, 2> no {'N', 'O'};
			std::copy(no.cbegin(), no.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(nonce.cbegin(), nonce.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		{
			c_vin vin;
			vin.m_txid.fill(0x00);
			vin.m_sign.fill(0x00);
			vin.m_pk = organizer_pk;
			tx_create_voting.m_vin.push_back(std::move(vin));
		}
		{
			c_vout vout;
			vout.m_pkh.fill(0x00);
			vout.m_amount = 0;
			tx_create_voting.m_vout.push_back(std::move(vout));
		}
		tx_create_voting.m_txid = c_txid_generate::generate_txid(tx_create_voting);
	}
	


	
	c_block genesis_block;
	genesis_block.m_header.m_version = n_blockchainparams::genesis_block_params::m_version;
	genesis_block.m_header.m_block_time = 1679183050;
	genesis_block.m_header.m_all_tx_hash = n_blockchainparams::genesis_block_params::m_all_tx_hash;
	genesis_block.m_header.m_parent_hash = n_blockchainparams::genesis_block_params::m_parent_hash;
	genesis_block.m_header.m_actual_hash = generate_block_hash(genesis_block.m_header);
	c_block block;
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_actual_hash = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_tx_hash = all_tx_hash;
	block.m_header.m_block_time = 1679079676;
	t_hash_type parent_hash;
	const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_parent_hash = parent_hash;
	block.m_header.m_version = 0;
	std::vector<c_transaction> txs;
	txs.resize(1);
	txs.at(0).m_vin.resize(1);
	txs.at(0).m_vout.resize(1);
	std::string txid_str;
	txid_str.resize(tx_create_voting.m_txid.size()*2+1);
	sodium_bin2hex(txid_str.data(), txid_str.size(), tx_create_voting.m_txid.data(), tx_create_voting.m_txid.size());
	std::string tx_allmetadata_str = "5649";
	tx_allmetadata_str += txid_str;
	tx_allmetadata_str.pop_back();
	txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=txs.at(0).m_txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txs.at(0).m_txid.data(), txs.at(0).m_txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_type = t_transactiontype::add_open_vote;
	const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
						tx_vin_pk_str.data(), tx_vin_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
						tx_vin_sign_str.data(), tx_vin_sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_vin.at(0).m_txid.fill(0x00);
	txs.at(0).m_vout.at(0).m_amount = 0;
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	const size_t height = 0;
	const size_t current_height = 1;
	using ::testing::Return;
	EXPECT_CALL(bc, get_transaction(tx_create_voting.m_txid))
	        .WillOnce(Return(tx_create_voting));
	EXPECT_CALL(bc, get_block_at_height(height))
	        .WillRepeatedly(Return(genesis_block));
	EXPECT_CALL(bc, get_current_height())
	        .WillOnce(Return(current_height));
	EXPECT_CALL(bc, get_block_at_height(current_height))
	        .WillRepeatedly(Return(block));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto voting_txs = bc_module->get_all_vote_transactions(tx_create_voting.m_txid);
	EXPECT_EQ(block.m_transaction, voting_txs);
}

TEST(blockchain_module, get_voter_groups) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<t_public_key_type> voter_groups;
	voter_groups.push_back(organizer_pk);

	using ::testing::Return;
	using ::testing::_;
	EXPECT_CALL(ut, get_parent_list_voter(voter_pk,_))
	        .WillOnce(Return(voter_groups));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto voter_groups_test = bc_module->get_voter_groups(voter_pk);
	EXPECT_EQ(voter_groups, voter_groups_test);
}

TEST(blockchain_module, get_all_inactive_votings) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";

	t_hash_type voting_id;
	const std::string voting_id_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
						voting_id_str.data(), voting_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	auto voting = std::make_pair(voting_id, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(voting);

	using ::testing::Return;
	EXPECT_CALL(ut, get_all_waiting_votings())
	        .WillOnce(Return(votings));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto votings_test = bc_module->get_all_inactive_votings();
	EXPECT_EQ(votings, votings_test);
}

TEST(blockchain_module, get_voter_auth_tx) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	c_block block;
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_actual_hash = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_all_tx_hash = all_tx_hash;
	block.m_header.m_block_time = 1679079676;
	t_hash_type parent_hash;
	const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_header.m_parent_hash = parent_hash;
	block.m_header.m_version = 0;
	std::vector<c_transaction> txs;
	txs.resize(1);
	txs.at(0).m_vin.resize(1);
	txs.at(0).m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
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
	txs.at(0).m_txid = txid;
	txs.at(0).m_type = t_transactiontype::authorize_voter;
	const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
						tx_vin_pk_str.data(), tx_vin_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
						tx_vin_sign_str.data(), tx_vin_sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	txs.at(0).m_vin.at(0).m_txid.fill(0x00);
	txs.at(0).m_vout.at(0).m_amount = 0;
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;
	std::vector<t_hash_type> txids;
	txids.push_back(txid);

	using ::testing::Return;
	EXPECT_CALL(ut, get_txids_of_tx_auth_voter(voter_pk))
	        .WillOnce(Return(txids));
	EXPECT_CALL(bc, get_transaction(txid))
	        .WillOnce(Return(txs.at(0)));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto voter_auth_txs = bc_module->get_voter_auth_tx(voter_pk);
	EXPECT_EQ(txs, voter_auth_txs);
}

TEST(blockchain_module, get_number_of_miners) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	const size_t number_of_miners = 2;
	using ::testing::Return;
	EXPECT_CALL(ut, get_number_of_miners())
	        .WillOnce(Return(number_of_miners));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto number_miners = bc_module->get_number_of_miners();
	EXPECT_EQ(number_of_miners, number_miners);
}

TEST(blockchain_module, get_all_added_votes) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";
	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	c_transaction tx_create_voting;
	tx_create_voting.m_type = t_transactiontype::create_voting;
	{
		// add question
		const auto question_metadata_value = get_metadata_variable_length_field("QS", voting_metadata.m_question);
		std::copy(question_metadata_value.cbegin(), question_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add voting options
		for (const auto & option : voting_metadata.m_options) {
			const auto option_metedata_value = get_metadata_variable_length_field("OP", option);
			std::copy(option_metedata_value.cbegin(), option_metedata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting name
		const auto voting_name_metadata_value = get_metadata_variable_length_field("VN", voting_metadata.m_name);
		std::copy(voting_name_metadata_value.cbegin(), voting_name_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add authorization level
		{
			const auto auth_level_as_array = get_array_byte(voting_metadata.m_authorization_level);
			const std::array<unsigned char, 2> al {'A', 'L'};
			std::copy(al.cbegin(), al.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(auth_level_as_array.cbegin(), auth_level_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of choice
		{
			const auto number_of_choice_as_array = get_array_byte(voting_metadata.m_number_of_choice);
			const std::array<unsigned char, 2> nc {'N', 'C'};
			std::copy(nc.cbegin(), nc.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_choice_as_array.cbegin(), number_of_choice_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of blocks to end
		{
			const auto number_of_blocks_as_array = get_array_byte(voting_metadata.m_number_of_blocks_to_the_end);
			const std::array<unsigned char, 2> be {'B', 'E'};
			std::copy(be.cbegin(), be.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_blocks_as_array.cbegin(), number_of_blocks_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add start timepoint
		{
			const auto unix_time_as_array = get_array_byte(voting_metadata.m_start_timepoint);
			const std::array<unsigned char, 2> st {'S', 'T'};
			std::copy(st.cbegin(), st.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(unix_time_as_array.cbegin(), unix_time_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting type - open or secret voting
		{
			const auto voting_type_array = get_array_byte(voting_metadata.m_voting_type);
			assert(voting_type_array.size()==1);
			const std::array<unsigned char, 2> vt {'V', 'T'};
			std::copy(vt.cbegin(), vt.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(voting_type_array.cbegin(), voting_type_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add nonce
		{
			std::array<unsigned char, 4> nonce;
			crypto_secure_random(&nonce[0], nonce.size());
			const std::array<unsigned char, 2> no {'N', 'O'};
			std::copy(no.cbegin(), no.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(nonce.cbegin(), nonce.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		{
			c_vin vin;
			vin.m_txid.fill(0x00);
			vin.m_sign.fill(0x00);
			vin.m_pk = organizer_pk;
			tx_create_voting.m_vin.push_back(std::move(vin));
		}
		{
			c_vout vout;
			vout.m_pkh.fill(0x00);
			vout.m_amount = 0;
			tx_create_voting.m_vout.push_back(std::move(vout));
		}
		tx_create_voting.m_txid = c_txid_generate::generate_txid(tx_create_voting);
	}

	std::vector<std::pair<t_hash_type, t_voting_metadata>> finished_votings;
	const auto finished_voting = std::make_pair(tx_create_voting.m_txid, voting_metadata);
	finished_votings.push_back(finished_voting);
	using ::testing::Return;
	std::vector<std::pair<t_hash_type, t_voting_metadata>> active_votings;
	active_votings.clear();
	EXPECT_CALL(ut, get_all_finished_votings())
	        .WillOnce(Return(finished_votings));
	EXPECT_CALL(ut, get_all_active_votings())
	        .WillOnce(Return(active_votings));
	EXPECT_CALL(bc, get_transaction(tx_create_voting.m_txid))
	        .WillOnce(Return(tx_create_voting));

	const auto option_A = container_to_vector_of_uchars(voting_metadata.m_options.at(0));
	std::vector<unsigned char> hash_input_A(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_A.cbegin(), option_A.cend(), std::back_inserter(hash_input_A));
	const auto option_address_A = generate_hash(hash_input_A);
	const auto option_B = container_to_vector_of_uchars(voting_metadata.m_options.at(1));
	std::vector<unsigned char> hash_input_B(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_B.cbegin(), option_B.cend(), std::back_inserter(hash_input_B));
	const auto option_address_B = generate_hash(hash_input_B);

	const size_t amount_added_votes_A = 45;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_A))
	        .WillRepeatedly(Return(amount_added_votes_A));
	const size_t amount_added_votes_B = 55;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_B))
	        .WillRepeatedly(Return(amount_added_votes_B));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto amount_added_votes_test = bc_module->get_all_added_votes();
	EXPECT_EQ(amount_added_votes_A + amount_added_votes_B, amount_added_votes_test);
}

TEST(blockchain_module, get_last_5_votings) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_hash_type voting_id_1;
	const std::string voting_id_1_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_1_str.size()!=voting_id_1.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id_1.data(), voting_id_1.size(),
						voting_id_1_str.data(), voting_id_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	const uint32_t voting_end_time = 1679189050;
	const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";

	auto voting = std::make_pair(voting_id_1, voting_metadata);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	votings.push_back(voting);
	t_hash_type voting_id_2;
	const std::string voting_id_2_str = "ffffd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_2_str.size()!=voting_id_2.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_2.data(), voting_id_2.size(),
						voting_id_2_str.data(), voting_id_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_2, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_3;
	const std::string voting_id_3_str = "ccefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_3_str.size()!=voting_id_3.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_3.data(), voting_id_3.size(),
						voting_id_3_str.data(), voting_id_3_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_3, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_4;
	const std::string voting_id_4_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_4_str.size()!=voting_id_4.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_4.data(), voting_id_4.size(),
						voting_id_4_str.data(), voting_id_4_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_4, voting_metadata);
	votings.push_back(voting);
	t_hash_type voting_id_5;
	const std::string voting_id_5_str = "eeefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_5_str.size()!=voting_id_5.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_5.data(), voting_id_5.size(),
						voting_id_5_str.data(), voting_id_5_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_5, voting_metadata);
	votings.push_back(voting);

	using ::testing::Return;
	EXPECT_CALL(ut, get_all_votings())
	        .WillRepeatedly(Return(votings));

	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2) {
		if(voting_1.first < voting_2.first) return true;
		else return false;
	});

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	auto votings_test = bc_module->get_last_5_votings();
	EXPECT_EQ(votings, votings_test);

	t_hash_type voting_id_6;
	const std::string voting_id_6_str = "ffefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_6_str.size()!=voting_id_6.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id_6.data(), voting_id_6.size(),
						voting_id_6_str.data(), voting_id_6_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	voting = std::make_pair(voting_id_6, voting_metadata);
	votings.push_back(voting);

	std::sort(votings.begin(), votings.end(),
	[](const std::pair<t_hash_type, t_voting_metadata> & voting_1, const std::pair<t_hash_type, t_voting_metadata> & voting_2) {
		if(voting_1.first < voting_2.first) return true;
		else return false;
	});

	EXPECT_CALL(ut, get_all_votings())
	        .WillRepeatedly(Return(votings));
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings_tmp;
	std::copy_n(votings.cbegin(), 5, std::back_inserter(votings_tmp));
	votings_test = bc_module->get_last_5_votings();
	EXPECT_EQ(votings_tmp, votings_test);
}

TEST(blockchain_module, get_voter_turnout_from_vote) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";
	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	c_transaction tx_create_voting;
	tx_create_voting.m_type = t_transactiontype::create_voting;
	{
		// add question
		const auto question_metadata_value = get_metadata_variable_length_field("QS", voting_metadata.m_question);
		std::copy(question_metadata_value.cbegin(), question_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add voting options
		for (const auto & option : voting_metadata.m_options) {
			const auto option_metedata_value = get_metadata_variable_length_field("OP", option);
			std::copy(option_metedata_value.cbegin(), option_metedata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting name
		const auto voting_name_metadata_value = get_metadata_variable_length_field("VN", voting_metadata.m_name);
		std::copy(voting_name_metadata_value.cbegin(), voting_name_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add authorization level
		{
			const auto auth_level_as_array = get_array_byte(voting_metadata.m_authorization_level);
			const std::array<unsigned char, 2> al {'A', 'L'};
			std::copy(al.cbegin(), al.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(auth_level_as_array.cbegin(), auth_level_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of choice
		{
			const auto number_of_choice_as_array = get_array_byte(voting_metadata.m_number_of_choice);
			const std::array<unsigned char, 2> nc {'N', 'C'};
			std::copy(nc.cbegin(), nc.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_choice_as_array.cbegin(), number_of_choice_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of blocks to end
		{
			const auto number_of_blocks_as_array = get_array_byte(voting_metadata.m_number_of_blocks_to_the_end);
			const std::array<unsigned char, 2> be {'B', 'E'};
			std::copy(be.cbegin(), be.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_blocks_as_array.cbegin(), number_of_blocks_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add start timepoint
		{
			const auto unix_time_as_array = get_array_byte(voting_metadata.m_start_timepoint);
			const std::array<unsigned char, 2> st {'S', 'T'};
			std::copy(st.cbegin(), st.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(unix_time_as_array.cbegin(), unix_time_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting type - open or secret voting
		{
			const auto voting_type_array = get_array_byte(voting_metadata.m_voting_type);
			assert(voting_type_array.size()==1);
			const std::array<unsigned char, 2> vt {'V', 'T'};
			std::copy(vt.cbegin(), vt.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(voting_type_array.cbegin(), voting_type_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add nonce
		{
			std::array<unsigned char, 4> nonce;
			crypto_secure_random(&nonce[0], nonce.size());
			const std::array<unsigned char, 2> no {'N', 'O'};
			std::copy(no.cbegin(), no.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(nonce.cbegin(), nonce.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		{
			c_vin vin;
			vin.m_txid.fill(0x00);
			vin.m_sign.fill(0x00);
			vin.m_pk = organizer_pk;
			tx_create_voting.m_vin.push_back(std::move(vin));
		}
		{
			c_vout vout;
			vout.m_pkh.fill(0x00);
			vout.m_amount = 0;
			tx_create_voting.m_vout.push_back(std::move(vout));
		}
		tx_create_voting.m_txid = c_txid_generate::generate_txid(tx_create_voting);
	}

	using ::testing::Return;
	EXPECT_CALL(bc, get_transaction(tx_create_voting.m_txid))
	        .WillOnce(Return(tx_create_voting));

	const auto option_A = container_to_vector_of_uchars(voting_metadata.m_options.at(0));
	std::vector<unsigned char> hash_input_A(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_A.cbegin(), option_A.cend(), std::back_inserter(hash_input_A));
	const auto option_address_A = generate_hash(hash_input_A);
	const auto option_B = container_to_vector_of_uchars(voting_metadata.m_options.at(1));
	std::vector<unsigned char> hash_input_B(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_B.cbegin(), option_B.cend(), std::back_inserter(hash_input_B));
	const auto option_address_B = generate_hash(hash_input_B);

	const size_t amount_added_votes_A = 45;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_A))
	        .WillRepeatedly(Return(amount_added_votes_A));
	const size_t amount_added_votes_B = 55;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_B))
	        .WillRepeatedly(Return(amount_added_votes_B));
	const size_t amount = amount_added_votes_A + amount_added_votes_B;

	const size_t number_voters = 200;
	using ::testing::_;
	EXPECT_CALL(ut, get_number_voters_in_group(tx_create_voting.m_vin.at(0).m_pk,_))
	        .WillOnce(Return(number_voters));

	const auto turnout = (amount * 100)/number_voters;

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto turnout_test = bc_module->get_voter_turnout_from_vote(tx_create_voting.m_txid);
	EXPECT_EQ(turnout, turnout_test);
}

TEST(blockchain_module, get_voting_result) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";
	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	c_transaction tx_create_voting;
	tx_create_voting.m_type = t_transactiontype::create_voting;
	{
		// add question
		const auto question_metadata_value = get_metadata_variable_length_field("QS", voting_metadata.m_question);
		std::copy(question_metadata_value.cbegin(), question_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add voting options
		for (const auto & option : voting_metadata.m_options) {
			const auto option_metedata_value = get_metadata_variable_length_field("OP", option);
			std::copy(option_metedata_value.cbegin(), option_metedata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting name
		const auto voting_name_metadata_value = get_metadata_variable_length_field("VN", voting_metadata.m_name);
		std::copy(voting_name_metadata_value.cbegin(), voting_name_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add authorization level
		{
			const auto auth_level_as_array = get_array_byte(voting_metadata.m_authorization_level);
			const std::array<unsigned char, 2> al {'A', 'L'};
			std::copy(al.cbegin(), al.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(auth_level_as_array.cbegin(), auth_level_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of choice
		{
			const auto number_of_choice_as_array = get_array_byte(voting_metadata.m_number_of_choice);
			const std::array<unsigned char, 2> nc {'N', 'C'};
			std::copy(nc.cbegin(), nc.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_choice_as_array.cbegin(), number_of_choice_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of blocks to end
		{
			const auto number_of_blocks_as_array = get_array_byte(voting_metadata.m_number_of_blocks_to_the_end);
			const std::array<unsigned char, 2> be {'B', 'E'};
			std::copy(be.cbegin(), be.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_blocks_as_array.cbegin(), number_of_blocks_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add start timepoint
		{
			const auto unix_time_as_array = get_array_byte(voting_metadata.m_start_timepoint);
			const std::array<unsigned char, 2> st {'S', 'T'};
			std::copy(st.cbegin(), st.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(unix_time_as_array.cbegin(), unix_time_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting type - open or secret voting
		{
			const auto voting_type_array = get_array_byte(voting_metadata.m_voting_type);
			assert(voting_type_array.size()==1);
			const std::array<unsigned char, 2> vt {'V', 'T'};
			std::copy(vt.cbegin(), vt.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(voting_type_array.cbegin(), voting_type_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add nonce
		{
			std::array<unsigned char, 4> nonce;
			crypto_secure_random(&nonce[0], nonce.size());
			const std::array<unsigned char, 2> no {'N', 'O'};
			std::copy(no.cbegin(), no.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(nonce.cbegin(), nonce.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		{
			c_vin vin;
			vin.m_txid.fill(0x00);
			vin.m_sign.fill(0x00);
			vin.m_pk = organizer_pk;
			tx_create_voting.m_vin.push_back(std::move(vin));
		}
		{
			c_vout vout;
			vout.m_pkh.fill(0x00);
			vout.m_amount = 0;
			tx_create_voting.m_vout.push_back(std::move(vout));
		}
		tx_create_voting.m_txid = c_txid_generate::generate_txid(tx_create_voting);
	}

	using ::testing::Return;
	EXPECT_CALL(bc, get_transaction(tx_create_voting.m_txid))
	        .WillOnce(Return(tx_create_voting));

	const auto option_A = container_to_vector_of_uchars(voting_metadata.m_options.at(0));
	std::vector<unsigned char> hash_input_A(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_A.cbegin(), option_A.cend(), std::back_inserter(hash_input_A));
	const auto option_address_A = generate_hash(hash_input_A);
	const auto option_B = container_to_vector_of_uchars(voting_metadata.m_options.at(1));
	std::vector<unsigned char> hash_input_B(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_B.cbegin(), option_B.cend(), std::back_inserter(hash_input_B));
	const auto option_address_B = generate_hash(hash_input_B);

	const size_t amount_option_address_A = 45;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_A))
	        .WillRepeatedly(Return(amount_option_address_A));
	const size_t amount_option_address_B = 55;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_B))
	        .WillRepeatedly(Return(amount_option_address_B));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto result = bc_module->get_voting_result(tx_create_voting.m_txid);
	auto it = result.find("option A");
	EXPECT_EQ(amount_option_address_A, it->second);
	it = result.find("option B");
	EXPECT_EQ(amount_option_address_B, it->second);
}

TEST(blockchain_module, get_voting_status) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_hash_type voting_id;
	const std::string voting_id_str = "ffefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
									voting_id_str.data(), voting_id_str.size(),
									nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	const unsigned char voting_status = 'X';
	using ::testing::Return;
	EXPECT_CALL(ut, get_voting_status(voting_id))
	        .WillOnce(Return(voting_status));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto voting_status_test = bc_module->get_voting_status(voting_id);
	EXPECT_EQ(voting_status, voting_status_test);
}

TEST(blockchain_module, get_hash_personal_data) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string hash_data_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	t_hash_type hash_data;
	if(hash_data_str.size()!=hash_data.size()*2) throw std::invalid_argument("Bad hash_data size");
	ret = sodium_hex2bin(hash_data.data(), hash_data.size(),
						hash_data_str.data(), hash_data_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(ut, get_hash_of_data_voter(voter_pk))
	        .WillOnce(Return(hash_data));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto hash_personal_data_test = bc_module->get_hash_personal_data(voter_pk);
	EXPECT_EQ(hash_data, hash_personal_data_test);
}

TEST(blockchain_module, get_number_of_all_voters_in_group) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	const size_t number_voters = 1000;
	using ::testing::Return;
	using ::testing::_;
	EXPECT_CALL(ut, get_number_voters_in_group(organizer_pk,_))
	        .WillOnce(Return(number_voters));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto number_voters_test = bc_module->get_number_of_all_voters_in_group(organizer_pk);
	EXPECT_EQ(number_voters, number_voters_test);
}

TEST(blockchain_module, get_voter_turnout_from_specific_votes) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_voting_metadata voting_metadata;
	voting_metadata.m_start_timepoint = 1679183050;
	uint32_t voting_end_time = 1679189050;
	uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
	uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
	voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
	voting_metadata.m_name = "Voting D";
	voting_metadata.m_voting_type = 0;
	voting_metadata.m_authorization_level = 1;
	voting_metadata.m_number_of_choice = 1;
	voting_metadata.m_options = {"option A", "option B"};
	voting_metadata.m_question = "Do you prefer option a or b?";
	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	c_transaction tx_create_voting;
	tx_create_voting.m_type = t_transactiontype::create_voting;
	{
		// add question
		const auto question_metadata_value = get_metadata_variable_length_field("QS", voting_metadata.m_question);
		std::copy(question_metadata_value.cbegin(), question_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add voting options
		for (const auto & option : voting_metadata.m_options) {
			const auto option_metedata_value = get_metadata_variable_length_field("OP", option);
			std::copy(option_metedata_value.cbegin(), option_metedata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting name
		const auto voting_name_metadata_value = get_metadata_variable_length_field("VN", voting_metadata.m_name);
		std::copy(voting_name_metadata_value.cbegin(), voting_name_metadata_value.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		// add authorization level
		{
			const auto auth_level_as_array = get_array_byte(voting_metadata.m_authorization_level);
			const std::array<unsigned char, 2> al {'A', 'L'};
			std::copy(al.cbegin(), al.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(auth_level_as_array.cbegin(), auth_level_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of choice
		{
			const auto number_of_choice_as_array = get_array_byte(voting_metadata.m_number_of_choice);
			const std::array<unsigned char, 2> nc {'N', 'C'};
			std::copy(nc.cbegin(), nc.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_choice_as_array.cbegin(), number_of_choice_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add number of blocks to end
		{
			const auto number_of_blocks_as_array = get_array_byte(voting_metadata.m_number_of_blocks_to_the_end);
			const std::array<unsigned char, 2> be {'B', 'E'};
			std::copy(be.cbegin(), be.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(number_of_blocks_as_array.cbegin(), number_of_blocks_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add start timepoint
		{
			const auto unix_time_as_array = get_array_byte(voting_metadata.m_start_timepoint);
			const std::array<unsigned char, 2> st {'S', 'T'};
			std::copy(st.cbegin(), st.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(unix_time_as_array.cbegin(), unix_time_as_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add voting type - open or secret voting
		{
			const auto voting_type_array = get_array_byte(voting_metadata.m_voting_type);
			assert(voting_type_array.size()==1);
			const std::array<unsigned char, 2> vt {'V', 'T'};
			std::copy(vt.cbegin(), vt.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(voting_type_array.cbegin(), voting_type_array.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		// add nonce
		{
			std::array<unsigned char, 4> nonce;
			crypto_secure_random(&nonce[0], nonce.size());
			const std::array<unsigned char, 2> no {'N', 'O'};
			std::copy(no.cbegin(), no.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
			std::copy(nonce.cbegin(), nonce.cend(), std::back_inserter(tx_create_voting.m_allmetadata));
		}
		{
			c_vin vin;
			vin.m_txid.fill(0x00);
			vin.m_sign.fill(0x00);
			vin.m_pk = organizer_pk;
			tx_create_voting.m_vin.push_back(std::move(vin));
		}
		{
			c_vout vout;
			vout.m_pkh.fill(0x00);
			vout.m_amount = 0;
			tx_create_voting.m_vout.push_back(std::move(vout));
		}
		tx_create_voting.m_txid = c_txid_generate::generate_txid(tx_create_voting);
	}

	using ::testing::Return;
	EXPECT_CALL(bc, get_transaction(tx_create_voting.m_txid))
	        .WillOnce(Return(tx_create_voting));

	const auto option_A = container_to_vector_of_uchars(voting_metadata.m_options.at(0));
	std::vector<unsigned char> hash_input_A(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_A.cbegin(), option_A.cend(), std::back_inserter(hash_input_A));
	const auto option_address_A = generate_hash(hash_input_A);
	const auto option_B = container_to_vector_of_uchars(voting_metadata.m_options.at(1));
	std::vector<unsigned char> hash_input_B(tx_create_voting.m_txid.cbegin(), tx_create_voting.m_txid.cend());
	std::copy(option_B.cbegin(), option_B.cend(), std::back_inserter(hash_input_B));
	const auto option_address_B = generate_hash(hash_input_B);

	const size_t amount_added_votes_A = 45;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_A))
	        .WillRepeatedly(Return(amount_added_votes_A));
	const size_t amount_added_votes_B = 55;
	EXPECT_CALL(ut, get_amount_on_pkh(option_address_B))
	        .WillRepeatedly(Return(amount_added_votes_B));
	const size_t amount = amount_added_votes_A + amount_added_votes_B;

	const size_t number_voters = 200;
	using ::testing::_;
	EXPECT_CALL(ut, get_number_voters_in_group(tx_create_voting.m_vin.at(0).m_pk,_))
	        .WillOnce(Return(number_voters));

	const auto turnout = (amount * 100)/number_voters;
	std::vector<std::pair<t_hash_type, double>> turnout_votings;
	const auto turnout_voting = std::make_pair(tx_create_voting.m_txid, turnout);
	turnout_votings.push_back(turnout_voting);

	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	const auto voting = std::make_pair(tx_create_voting.m_txid, voting_metadata);
	votings.push_back(voting);

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto votings_turnout_test = bc_module->get_voter_turnout_from_specific_votes(votings);
	EXPECT_EQ(turnout_votings, votings_turnout_test);
}
