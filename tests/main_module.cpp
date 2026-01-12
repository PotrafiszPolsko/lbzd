#include <gtest/gtest.h>
#include "../src/main_module.hpp"
#include "../src/serialization_utils.hpp"
#include "blockchain_module_mock.hpp"
#include "p2p_module_mock.hpp"
#include "wallet_module_interface_mock.hpp"
#include "main_module_mock_builder.hpp"

TEST(main_module, add_new_block) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	EXPECT_CALL(bc_module, add_new_block(block))
	        .WillOnce(
	            [block](const c_block &block_tmp){
		return block==block_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_add_new_block request;
	request.m_block = block;
	main_module->notify(request);
}

TEST(main_module, add_new_transaction_full_tx) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	tx.m_type = t_transactiontype::authorize_organizer;
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
	const std::string tx_vin_txid_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
	ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
						tx_vin_txid_str.data(), tx_vin_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	EXPECT_CALL(bc_module, add_new_transaction(tx))
	        .WillOnce(
	            [tx](const c_transaction &tx_tmp){
		return tx==tx_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_add_new_transaction request;
	request.m_transaction = tx;
	const auto response = main_module->notify(request);
	const auto &response_add_tx = dynamic_cast<const t_mediator_command_response_add_new_transaction&>(*response);
	EXPECT_TRUE(response_add_tx.m_tx_added_to_mempool);
}

TEST(main_module, add_transaction_to_mempool) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

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
	t_hash_type txid;
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	tx.m_txid = txid;
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_type = t_transactiontype::authorize_organizer;
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	const bool is_tx_in_bc = false;
	using ::testing::Return;
	EXPECT_CALL(bc_module, is_transaction_in_blockchain(txid))
	        .WillOnce(Return(is_tx_in_bc));

	EXPECT_CALL(bc_module, add_new_transaction(tx))
	        .WillOnce(
	            [tx](const c_transaction &tx_tmp){
		return tx==tx_tmp;
	});

	using ::testing::_;
	EXPECT_CALL(pp_module, broadcast_transaction(_))
	        .WillOnce(
				[&tx](const c_transaction & tx_tmp) {
		return tx == tx_tmp;
	});
	
	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_add_transaction_to_mempool request;
	request.m_tx = tx;
	main_module->notify(request);
}

TEST(main_module, broadcast_block) {
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	EXPECT_CALL(pp_module, broadcast_block(block))
	        .WillOnce(
	            [&block](const c_block & block_tmp) {
		return block == block_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_broadcast_block request;
	request.m_block = block;
	main_module->notify(request);
}

TEST(main_module, broadcast_transaction) {
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

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
	t_hash_type txid;
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	tx.m_txid = txid;
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_type = t_transactiontype::authorize_organizer;
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

	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::_;
	EXPECT_CALL(pp_module, broadcast_transaction(_))
	        .WillOnce(
				[&tx](const c_transaction & tx_tmp) {
		return tx == tx_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_broadcast_transaction request;
	request.m_transaction = tx;
	main_module->notify(request);
}

TEST(main_module, get_tx) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	int ret = 1;
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	c_transaction tx;
	tx.m_txid = txid;
	tx.m_vin.resize(1);;
	tx.m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_type = t_transactiontype::authorize_organizer;
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_transaction(txid))
	        .WillOnce(Return(tx));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_tx request;
	request.m_txid = txid;
	const auto response = main_module->notify(request);
	const auto &response_get_tx = dynamic_cast<const t_mediator_command_response_get_tx&>(*response);
	EXPECT_EQ(tx, response_get_tx.m_transaction);
}

TEST(main_module, get_block_by_height) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;
	const size_t height = 30;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_at_height(height))
	        .WillOnce(Return(block));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_by_height request;
	request.m_height = height;
	const auto response = main_module->notify(request);
	const auto &response_get_block_by_height = dynamic_cast<const t_mediator_command_response_get_block_by_height&>(*response);
	EXPECT_EQ(block, response_get_block_by_height.m_block);
}

TEST(main_module, get_block_by_id) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_at_hash(actual_hash))
	        .WillOnce(Return(block));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_by_id request;
	request.m_block_hash = actual_hash;
	const auto response = main_module->notify(request);
	const auto &response_get_block_by_id = dynamic_cast<const t_mediator_command_response_get_block_by_id&>(*response);
	EXPECT_EQ(block, response_get_block_by_id.m_block);
}

TEST(main_module, get_last_block_hash) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_last_block_hash())
	        .WillOnce(Return(actual_hash));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_last_block_hash request;
	const auto response = main_module->notify(request);
	const auto &response_get_last_block_hash = dynamic_cast<const t_mediator_command_response_get_last_block_hash&>(*response);
	EXPECT_EQ(actual_hash, response_get_last_block_hash.m_last_block_hash);
}

TEST(main_module, get_mempool_size) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t number_txs = 20;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_number_of_mempool_transactions)
	        .WillOnce(Return(number_txs));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_mempool_size request;
	const auto response = main_module->notify(request);
	const auto &response_get_mempool_size = dynamic_cast<const t_mediator_command_response_get_mempool_size&>(*response);
	EXPECT_EQ(number_txs, response_get_mempool_size.m_number_of_transactions);
}

TEST(main_module, get_mempool_transactions) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	int ret = 1;
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	c_transaction tx;
	tx.m_txid = txid;
	tx.m_vin.resize(1);;
	tx.m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_type = t_transactiontype::authorize_organizer;
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<c_transaction> txs;
	txs.push_back(tx);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_mempool_transactions())
	        .WillOnce(Return(txs));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_mempool_transactions request;
	const auto response = main_module->notify(request);
	const auto &response_get_mempool_txs = dynamic_cast<const t_mediator_command_response_get_mempool_transactions&>(*response);
	EXPECT_EQ(tx, response_get_mempool_txs.m_transactions.at(0));
}

TEST(main_module, get_block_by_id_proto) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;
	const auto block_proto = block_to_protobuf(block);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_at_hash_proto(actual_hash))
	        .WillOnce(Return(block_proto));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_by_id_proto request;
	request.m_block_hash = actual_hash;
	const auto response = main_module->notify(request);
	const auto &response_get_block_by_id_proto = dynamic_cast<const t_mediator_command_response_get_block_by_id_proto&>(*response);
	EXPECT_EQ(block, block_from_protobuf(response_get_block_by_id_proto.m_block_proto));
}

TEST(main_module, get_headers_proto) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	c_header header;
	t_hash_type actual_hash;
	const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header.m_actual_hash = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header.m_all_tx_hash = all_tx_hash;
	header.m_block_time = 1679079676;
	t_hash_type parent_hash;
	const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header.m_parent_hash = parent_hash;
	header.m_version = 0;
	const auto header_proto = header_to_protobuf(header);
	std::vector<proto::header> headers_proto;
	headers_proto.push_back(header_proto);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_headers_proto(actual_hash, actual_hash))
	        .WillOnce(Return(headers_proto));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_headers_proto request;
	request.m_hash_begin = actual_hash;
	request.m_hash_end = actual_hash;
	const auto response = main_module->notify(request);
	const auto &response_get_headers_proto = dynamic_cast<const t_mediator_command_response_get_headers_proto&>(*response);
	EXPECT_EQ(header, header_from_protobuf(response_get_headers_proto.m_headers.at(0)));
}

TEST(main_module, is_organizer_pk) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	t_public_key_type pk;
	const std::string pk_str = "10aa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	const auto ret = sodium_hex2bin(pk.data(), pk.size(),
									pk_str.data(), pk_str.size(),
									nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	const bool is_organizer_pk = true;
	using ::testing::Return;
	EXPECT_CALL(bc_module, is_pk_organizer(pk))
	        .WillOnce(Return(is_organizer_pk));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_organizer_pk request;
	request.m_pk = pk;
	const auto response = main_module->notify(request);
	const auto &response_is_pk_organizer = dynamic_cast<const t_mediator_command_response_is_organizer_pk&>(*response);
	EXPECT_TRUE(response_is_pk_organizer.m_is_organizer_pk);
}

TEST(main_module, get_height) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	const size_t height = 100;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_height())
	        .WillRepeatedly(Return(height));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_height request;
	const auto response = main_module->notify(request);
	const auto &response_get_height = dynamic_cast<const t_mediator_command_response_get_height&>(*response);
	EXPECT_EQ(height, response_get_height.m_height);
}

TEST(main_module, is_authorized_organizer) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_public_key_type pk;
	const std::string pk_str = "10aa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = sodium_hex2bin(pk.data(), pk.size(),
							pk_str.data(), pk_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	using ::testing::Return;
	EXPECT_CALL(bc_module, get_auth_txid(pk))
	        .WillRepeatedly(Return(txid));
	EXPECT_CALL(bc_module, is_pk_miner(pk))
	        .WillRepeatedly(Return(false));
	EXPECT_CALL(bc_module, is_pk_organizer(pk))
	        .WillRepeatedly(Return(true));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_authorized request;
	request.m_pk = pk;
	const auto response = main_module->notify(request);
	const auto &response_is_authorized = dynamic_cast<const t_mediator_command_response_is_authorized&>(*response);
	EXPECT_FALSE(response_is_authorized.m_is_adminsys);
	EXPECT_FALSE(response_is_authorized.m_is_miner);
	EXPECT_TRUE(response_is_authorized.m_is_organizer);
	EXPECT_EQ(response_is_authorized.m_txid_auth, txid);
}

TEST(main_module, is_authorized_miner) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_public_key_type pk;
	const std::string pk_str = "10aa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = sodium_hex2bin(pk.data(), pk.size(),
							pk_str.data(), pk_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	using ::testing::Return;
	EXPECT_CALL(bc_module, get_auth_txid(pk))
	        .WillRepeatedly(Return(txid));
	EXPECT_CALL(bc_module, is_pk_miner(pk))
	        .WillRepeatedly(Return(true));
	EXPECT_CALL(bc_module, is_pk_organizer(pk))
	        .WillRepeatedly(Return(false));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_authorized request;
	request.m_pk = pk;
	const auto response = main_module->notify(request);
	const auto &response_is_authorized = dynamic_cast<const t_mediator_command_response_is_authorized&>(*response);
	EXPECT_FALSE(response_is_authorized.m_is_adminsys);
	EXPECT_TRUE(response_is_authorized.m_is_miner);
	EXPECT_FALSE(response_is_authorized.m_is_organizer);
	EXPECT_EQ(response_is_authorized.m_txid_auth, txid);
}

TEST(main_module, is_authorized_adminsys) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_public_key_type pk;
	pk = n_blockchainparams::admins_sys_pub_keys.at(0);
	t_hash_type txid;
	txid.fill(0x00);
	using ::testing::Return;
	EXPECT_CALL(bc_module, get_auth_txid(pk))
	        .WillRepeatedly(Return(txid));
	EXPECT_CALL(bc_module, is_pk_miner(pk))
	        .WillRepeatedly(Return(false));
	EXPECT_CALL(bc_module, is_pk_organizer(pk))
	        .WillRepeatedly(Return(false));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_authorized request;
	request.m_pk = pk;
	const auto response = main_module->notify(request);
	const auto &response_is_authorized = dynamic_cast<const t_mediator_command_response_is_authorized&>(*response);
	EXPECT_TRUE(response_is_authorized.m_is_adminsys);
	EXPECT_FALSE(response_is_authorized.m_is_miner);
	EXPECT_FALSE(response_is_authorized.m_is_organizer);
	EXPECT_EQ(response_is_authorized.m_txid_auth, txid);
}

TEST(main_module, is_authorized_nobody) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_public_key_type pk;
	pk.fill(0x00);
	using ::testing::Return;
	EXPECT_CALL(bc_module, is_pk_miner(pk))
	        .WillRepeatedly(Return(false));
	EXPECT_CALL(bc_module, is_pk_organizer(pk))
	        .WillRepeatedly(Return(false));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_authorized request;
	request.m_pk = pk;
	EXPECT_THROW(main_module->notify(request), std::runtime_error);
}

TEST(main_module, get_metadata_from_tx) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	int ret = 1;
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	c_transaction tx;
	tx.m_txid = txid;
	const std::string tx_allmetadata_str = "434ffec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24414C00000003504Bc2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_transaction(txid))
	        .WillOnce(Return(tx));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_metadata_from_tx request;
	request.m_txid = txid;
	const auto response = main_module->notify(request);
	const auto &response_get_metadata_from_tx = dynamic_cast<const t_mediator_command_response_get_metadata_from_tx&>(*response);
	EXPECT_EQ(tx.m_allmetadata, response_get_metadata_from_tx.m_metadata_from_tx);
}

TEST(main_module, get_last_block_time) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t block_time = 1679079676;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_last_block_time())
	        .WillOnce(Return(block_time));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_last_block_time request;
	const auto response = main_module->notify(request);
	const auto &response_get_last_block_time = dynamic_cast<const t_mediator_command_response_get_last_block_time&>(*response);
	EXPECT_EQ(block_time, response_get_last_block_time.m_block_time);
}

TEST(main_module, get_block_by_txid) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
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
	const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
	if(tx_vin_txid_str.size()!=txs.at(0).m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_txid.data(), txs.at(0).m_vin.at(0).m_txid.size(),
						tx_vin_txid_str.data(), tx_vin_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_by_txid(txid))
	        .WillOnce(Return(block));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_by_txid request;
	request.m_txid = txid;
	const auto response = main_module->notify(request);
	const auto &response_get_block_by_txid = dynamic_cast<const t_mediator_command_response_get_block_by_txid&>(*response);
	EXPECT_EQ(block, response_get_block_by_txid.m_block);
}

TEST(main_module, get_merkle_branch) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	t_hash_type block_id;
	const std::string block_id_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(block_id_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(block_id.data(), block_id.size(),
						block_id_str.data(), block_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<t_hash_type> merkle_branch;
	merkle_branch.push_back(hash_merkle_root);
	merkle_branch.push_back(hash_merkle);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_merkle_branch(txid))
	        .WillOnce(Return(merkle_branch));
	EXPECT_CALL(bc_module, get_block_id_by_txid(txid))
	        .WillOnce(Return(block_id));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_merkle_branch request;
	request.m_txid = txid;
	const auto response = main_module->notify(request);
	const auto &response_get_merkle_branch = dynamic_cast<const t_mediator_command_response_get_merkle_branch&>(*response);
	EXPECT_EQ(merkle_branch, response_get_merkle_branch.m_merkle_branch);
	EXPECT_EQ(block_id, response_get_merkle_branch.m_block_id);
}

TEST(main_module, get_number_of_miners) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t number_of_miners = 12;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_number_of_miners())
	        .WillOnce(Return(number_of_miners));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_miners request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_of_miners = dynamic_cast<const t_mediator_command_response_get_number_of_miners&>(*response);
	EXPECT_EQ(number_of_miners, response_get_number_of_miners.m_number_of_miners);
}

TEST(main_module, get_number_of_all_transactions) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t number_of_all_transactions = 40789;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_number_of_transactions())
	        .WillOnce(Return(number_of_all_transactions));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_all_transactions request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_of_all_transactions = dynamic_cast<const t_mediator_command_response_get_number_of_all_transactions&>(*response);
	EXPECT_EQ(number_of_all_transactions, response_get_number_of_all_transactions.m_number_of_all_transactions);
}

TEST(main_module, get_block_by_id_without_txs_and_signs) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_at_hash(actual_hash))
	        .WillOnce(Return(block));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_by_id_without_txs_and_signs request;
	request.m_block_hash = actual_hash;
	const auto response = main_module->notify(request);
	const auto &response_get_block_by_id = dynamic_cast<const t_mediator_command_response_get_block_by_id_without_txs_and_signs&>(*response);
	EXPECT_EQ(block, response_get_block_by_id.m_block);
}

TEST(main_module, get_block_by_height_without_txs_and_signs) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;
	const size_t height = 30;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_at_height(height))
	        .WillOnce(Return(block));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_by_height_without_txs_and_signs request;
	request.m_height = height;
	const auto response = main_module->notify(request);
	const auto &response_get_block_by_height = dynamic_cast<const t_mediator_command_response_get_block_by_height_without_txs_and_signs&>(*response);
	EXPECT_EQ(block, response_get_block_by_height.m_block);
}

TEST(main_module, get_block_by_txid_without_txs_and_signs) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
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
	const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
	if(tx_vin_txid_str.size()!=txs.at(0).m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
	ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_txid.data(), txs.at(0).m_vin.at(0).m_txid.size(),
						tx_vin_txid_str.data(), tx_vin_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_by_txid(txid))
	        .WillOnce(Return(block));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_by_txid_without_txs_and_signs request;
	request.m_txid = txid;
	const auto response = main_module->notify(request);
	const auto &response_get_block_by_txid = dynamic_cast<const t_mediator_command_response_get_block_by_txid_without_txs_and_signs&>(*response);
	EXPECT_EQ(block, response_get_block_by_txid.m_block);
}

TEST(main_module, get_sorted_blocks) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const size_t amount_blocks = 5;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_sorted_blocks(amount_blocks))
	        .WillOnce(Return(blocks_record));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_sorted_blocks_without_txs_and_signs request;
	request.m_amount_of_blocks = amount_blocks;
	const auto response = main_module->notify(request);
	const auto &response_get_sorted_blocks = dynamic_cast<const t_mediator_command_response_get_sorted_blocks_without_txs_and_signs&>(*response);
	EXPECT_EQ(blocks_record, response_get_sorted_blocks.m_blocks);
}

TEST(main_module, get_sorted_blocks_per_page) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	EXPECT_CALL(bc_module, get_sorted_blocks_per_page(offset))
	        .WillOnce(Return(blocks_per_page));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs request;
	request.m_offset = 1;
	const auto response = main_module->notify(request);
	const auto &response_get_sorted_blocks_per_page = dynamic_cast<const t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs&>(*response);
	EXPECT_EQ(blocks_record, response_get_sorted_blocks_per_page.m_blocks);
	EXPECT_EQ(current_height, response_get_sorted_blocks_per_page.m_current_height);
}

TEST(main_module, get_latest_txs) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		const std::string tx_vout_pkh_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
	const size_t amount_txs = 5;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_latest_transactions(amount_txs))
	        .WillOnce(Return(txs));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_latest_txs request;
	request.m_amount_txs = amount_txs;
	const auto response = main_module->notify(request);
	const auto &response_get_latest_transactions = dynamic_cast<const t_mediator_command_response_get_latest_txs&>(*response);
	EXPECT_EQ(txs, response_get_latest_transactions.m_transactions);
}

TEST(main_module, get_txs_per_page) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
	EXPECT_CALL(bc_module, get_txs_per_page(offset))
	        .WillOnce(Return(txs_per_page));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_txs_per_page request;
	request.m_offset = offset;
	const auto response = main_module->notify(request);
	const auto &response_get_transactions_per_page = dynamic_cast<const t_mediator_command_response_get_txs_per_page&>(*response);
	EXPECT_EQ(txs, response_get_transactions_per_page.m_transactions);
	EXPECT_EQ(amount_txs, response_get_transactions_per_page.m_total_number_txs);
}

TEST(main_module, get_txs_from_block_per_page) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		tx.m_type = t_transactiontype::authorize_organizer;
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
		const std::string tx_vout_pkh_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
		if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
		ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
							tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		txs.push_back(tx);
	}
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
	EXPECT_CALL(bc_module, get_txs_from_block_per_page(offset, block_id))
	        .WillOnce(Return(txs_per_page));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_txs_from_block_per_page request;
	request.m_offset = offset;
	request.m_block_id = block_id;
	const auto response = main_module->notify(request);
	const auto &response_get_transactions_from_block_per_page = dynamic_cast<const t_mediator_command_response_get_txs_from_block_per_page&>(*response);
	EXPECT_EQ(txs, response_get_transactions_from_block_per_page.m_transactions);
	EXPECT_EQ(amount_txs, response_get_transactions_from_block_per_page.m_number_txs);
}

TEST(main_module, get_block_signatures_and_pk_miners_per_page) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const std::string miner_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
	t_public_key_type miner_pk;
	if(miner_pk_str.size()!=miner_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(miner_pk.data(), miner_pk.size(),
						miner_pk_str.data(), miner_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string miner_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	t_signature_type miner_sign;
	if(miner_sign_str.size()!=miner_sign.size()*2) throw std::invalid_argument("Bad sign size");
	ret = sodium_hex2bin(miner_sign.data(), miner_sign.size(),
						miner_sign_str.data(), miner_sign_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string block_id_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	t_hash_type block_id;
	if(block_id_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad block_id size");
	ret = sodium_hex2bin(block_id.data(), block_id.size(),
						block_id_str.data(), block_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const size_t offset = 1;
	const size_t number_of_signs = 1;
	std::vector<std::pair<t_signature_type, t_public_key_type>> signatures_and_pks;
	signatures_and_pks.push_back(std::make_pair(miner_sign, miner_pk));
	const auto signatures_and_pks_with_total_number = std::make_pair(signatures_and_pks, number_of_signs);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_block_signatures_and_pk_miners_per_page(offset, block_id))
	        .WillOnce(Return(signatures_and_pks_with_total_number));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_block_signatures_and_pks_miners_per_page request;
	request.m_offset = offset;
	request.m_block_id = block_id;
	const auto response = main_module->notify(request);
	const auto &response_get_sign_and_pk_miners = dynamic_cast<const t_mediator_command_response_get_block_signatures_and_pks_miners_per_page&>(*response);
	EXPECT_EQ(signatures_and_pks, response_get_sign_and_pk_miners.m_signatures_and_pks);
	EXPECT_EQ(number_of_signs, response_get_sign_and_pk_miners.m_number_signatures);
}

TEST(main_module, get_peers) {
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

	const std::string address_tcp_str = "91.236.233.26";
	const unsigned short port = 33333;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);

	std::vector<std::unique_ptr<c_peer_reference> > peer_ref_vec_with_tcp;
	peer_ref_vec_with_tcp.push_back(std::move(peer_ref_from_tcp));

	EXPECT_CALL(pp_module, get_peers_tcp())
	        .WillOnce(
	            []() -> std::vector<std::unique_ptr<c_peer_reference> > {
	                const std::string address_tcp_str = "91.236.233.26";
					const unsigned short port = 33333;
					auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	                std::vector<std::unique_ptr<c_peer_reference> > peer_ref_vec_with_tcp;
					peer_ref_vec_with_tcp.push_back(std::move(peer_ref_from_tcp));
	                return peer_ref_vec_with_tcp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_peers request;
	const auto response = main_module->notify(request);
	const auto &response_get_peers = dynamic_cast<const t_mediator_command_response_get_peers&>(*response);
	const auto peer_tcp = dynamic_cast<c_peer_reference_tcp&>(*response_get_peers.m_peers_tcp.at(0));
	EXPECT_EQ("91.236.233.26:33333", peer_tcp.to_string());
}

TEST(main_module, authorize_organizer_by_adminsys) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl_module, get_main_pk())
	        .WillOnce(Return(n_blockchainparams::admins_sys_pub_keys.at(0)));

	EXPECT_CALL(bc_module, authorize_organizer_by_adminsys(organizer_pk, n_blockchainparams::admins_sys_pub_keys.at(0)))
	        .WillOnce(Return(tx));

	const bool is_added_to_mempool = true;
	EXPECT_CALL(bc_module, add_new_transaction(tx))
	        .WillOnce(Return(is_added_to_mempool));

	using ::testing::_;
	EXPECT_CALL(pp_module, broadcast_transaction(_))
	        .WillOnce(
				[&tx](const c_transaction & tx_tmp) {
		return tx == tx_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_authorize_organizer_by_admin request;
	request.m_organizer_pk = organizer_pk;
	const auto response = main_module->notify(request);
	const auto &response_get_auth_tx = dynamic_cast<const t_mediator_command_response_authorize_organizer_by_admin&>(*response);
	EXPECT_EQ(txid, response_get_auth_tx.m_txid_auth_organizer);
}

TEST(main_module, authorize_miner_by_adminsys) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	t_public_key_type miner_pk;
	const std::string miner_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(miner_pk_str.size()!=miner_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(miner_pk.data(), miner_pk.size(),
						miner_pk_str.data(), miner_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl_module, get_main_pk())
	        .WillOnce(Return(n_blockchainparams::admins_sys_pub_keys.at(0)));

	EXPECT_CALL(bc_module, authorize_miner_by_adminsys(miner_pk, n_blockchainparams::admins_sys_pub_keys.at(0)))
	        .WillOnce(Return(tx));

	const bool is_added_to_mempool = true;
	EXPECT_CALL(bc_module, add_new_transaction(tx))
	        .WillOnce(Return(is_added_to_mempool));

	using ::testing::_;
	EXPECT_CALL(pp_module, broadcast_transaction(_))
	        .WillOnce(
				[&tx](const c_transaction & tx_tmp) {
		return tx == tx_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_authorize_miner_by_admin request;
	request.m_miner_pk = miner_pk;
	const auto response = main_module->notify(request);
	const auto &response_get_auth_tx = dynamic_cast<const t_mediator_command_response_authorize_miner_by_admin&>(*response);
	EXPECT_EQ(txid, response_get_auth_tx.m_txid_auth_miner);
}

TEST(main_module, set_key_from_mnemonic) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);

	const std::array<std::string, 12> seed_words = {"style","coil","alcohol","horn","industry","blind",
	                                                "nerve","blind","final","pigeon","off","brown"};
	EXPECT_CALL(wl_module, generate_seed_from_words(seed_words))
	        .WillOnce(
	            [&seed_words](const std::array<std::string, 12> & seed_words_tmp){
		return seed_words == seed_words_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_set_key_from_mnemonic request;
	request.m_seed_words = seed_words;
	const auto response = main_module->notify(request);
}

TEST(main_module, add_voting_protocol) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

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
	const std::string tx_txid_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_txid = txid;
	tx.m_type = t_transactiontype::another_voting_protocol;
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
	const std::string tx_vin_txid_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(tx_vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
	ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
						tx_vin_txid_str.data(), tx_vin_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	t_public_key_type organizer_pk;
	const std::string organizer_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl_module, get_main_pk())
	        .WillOnce(Return(organizer_pk));

	const bool is_organizer_pk = true;
	EXPECT_CALL(bc_module, is_pk_organizer(organizer_pk))
	        .WillOnce(Return(is_organizer_pk));

	const std::string voting_data_str = "8572f7a74dd92ee5bb5638f57d1bbfef9514720b5d29a9d0d0d78ff6a642181d";
	const auto voting_data_vec = container_to_vector_of_uchars(voting_data_str);
	EXPECT_CALL(bc_module, add_voting_protocol(voting_data_vec, organizer_pk))
	        .WillOnce(Return(tx));

	const bool is_tx_in_bc = false;
	EXPECT_CALL(bc_module, is_transaction_in_blockchain(txid))
	        .WillOnce(Return(is_tx_in_bc));

	const bool is_added_to_mempool = true;
	EXPECT_CALL(bc_module, add_new_transaction(tx))
	        .WillOnce(Return(is_added_to_mempool));

	using ::testing::_;
	EXPECT_CALL(pp_module, broadcast_transaction(_))
	        .WillOnce(
				[&tx](const c_transaction & tx_add_vote_tmp) {
		return tx == tx_add_vote_tmp;
	});

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_add_voting_protocol request;
	request.m_voting_protocol = voting_data_vec;
	const auto response = main_module->notify(request);
	const auto &response_add_voting_protocol = dynamic_cast<const t_mediator_command_response_add_voting_protocol&>(*response);
	EXPECT_EQ(txid, response_add_voting_protocol.m_txid);
}

TEST(main_module, get_mnemonic_sentence) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);

	const std::array<std::string, 12> seed_words = {"style","coil","alcohol","horn","industry","blind",
	                                                "nerve","blind","final","pigeon","off","brown"};
	using ::testing::Return;
	EXPECT_CALL(wl_module, get_words_of_seed())
	        .WillOnce(Return(seed_words));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_mnemonic_sentence request;
	main_module->notify(request);
}

TEST(main_module, get_pk_and_sign) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);

	t_public_key_type pk;
	const std::string pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(pk.data(), pk.size(),
						pk_str.data(), pk_str.size(),
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
	EXPECT_CALL(wl_module, get_main_pk())
	        .WillOnce(Return(pk));

	const std::string message = {"message_to_sign"};
	EXPECT_CALL(wl_module, sign_message_using_main_pk(message))
	        .WillOnce(Return(sign));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_pk_and_sign request;
	request.m_msg_to_sign = message;
	const auto response = main_module->notify(request);
	const auto &response_get_pk_and_sign = dynamic_cast<const t_mediator_command_response_get_pk_and_sign&>(*response);
	EXPECT_EQ(pk, response_get_pk_and_sign.m_pk);
	EXPECT_EQ(sign, response_get_pk_and_sign.m_sign);
}

TEST(main_module, sign_message_by_main_identity) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);

	t_signature_type sign;
	const std::string sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
	const auto ret = sodium_hex2bin(sign.data(), sign.size(),
									sign_str.data(), sign_str.size(),
									nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	const std::string message = {"message_to_sign"};
	EXPECT_CALL(wl_module, sign_message_using_main_pk(message))
	        .WillOnce(Return(sign));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_sign_message_by_main_identity request;
	request.m_msg = message;
	const auto response = main_module->notify(request);
	const auto &response_get_sign = dynamic_cast<const t_mediator_command_response_sign_message_by_main_identity&>(*response);
	EXPECT_EQ(sign, response_get_sign.m_sign);
}

TEST(main_module, sign_tx_by_main_identity) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);

	c_transaction tx_to_sign;
	t_signature_type sign;
	const std::string sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
	if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
	const auto ret = sodium_hex2bin(sign.data(), sign.size(),
									sign_str.data(), sign_str.size(),
									nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl_module, sign_tx_by_main_identity(tx_to_sign))
	        .WillOnce(Return(sign));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_sign_tx_by_main_identity request;
	request.m_transaction_to_sign = tx_to_sign;
	const auto response = main_module->notify(request);
	const auto &response_get_sign = dynamic_cast<const t_mediator_command_response_sign_tx_by_main_identity&>(*response);
	EXPECT_EQ(sign, response_get_sign.m_transaction_signature);
}

TEST(main_module, get_pk) {
	std::unique_ptr<c_wallet_module_interface> wallet_module = std::make_unique<c_wallet_module_mock>();
	c_wallet_module_mock &wl_module = dynamic_cast<c_wallet_module_mock&>(*wallet_module);

	t_public_key_type pk;
	const std::string pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(pk.data(), pk.size(),
						pk_str.data(), pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	using ::testing::Return;
	EXPECT_CALL(wl_module, get_main_pk())
	        .WillOnce(Return(pk));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_wallet_module_interface(std::move(wallet_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_pk request;
	const auto response = main_module->notify(request);
	const auto &response_get_pk = dynamic_cast<const t_mediator_command_response_get_pk&>(*response);
	EXPECT_EQ(pk, response_get_pk.m_pk);
}

TEST(main_module, block_exists_true) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
	                    tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
	                    nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc_module, block_exists(actual_hash))
	        .WillOnce(Return(true));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_block_exists request;
	request.m_block_id = actual_hash;
	const auto response = main_module->notify(request);
	const auto &response_block_exists = dynamic_cast<const t_mediator_command_response_block_exists&>(*response);
	EXPECT_TRUE(response_block_exists.m_block_exists);
}

TEST(main_module, block_exists_false) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
	                    tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
	                    nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc_module, block_exists(actual_hash))
	        .WillOnce(Return(false));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_block_exists request;
	request.m_block_id = actual_hash;
	const auto response = main_module->notify(request);
	const auto &response_block_exists = dynamic_cast<const t_mediator_command_response_block_exists&>(*response);
	EXPECT_FALSE(response_block_exists.m_block_exists);
}

TEST(main_module, is_blockchain_synchronized_false) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	using ::testing::Return;
	EXPECT_CALL(bc_module, is_blockchain_synchronized())
	        .WillOnce(Return(false));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_blockchain_synchronized request;
	const auto response = main_module->notify(request);
	const auto &response_blockchain_synchronized = dynamic_cast<const t_mediator_command_response_is_blockchain_synchronized&>(*response);
	EXPECT_FALSE(response_blockchain_synchronized.m_is_blockchain_synchronized);
}

TEST(main_module, is_blockchain_synchronized_true) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	using ::testing::Return;
	EXPECT_CALL(bc_module, is_blockchain_synchronized())
	        .WillOnce(Return(true));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_blockchain_synchronized request;
	const auto response = main_module->notify(request);
	const auto &response_blockchain_synchronized = dynamic_cast<const t_mediator_command_response_is_blockchain_synchronized&>(*response);
	EXPECT_TRUE(response_blockchain_synchronized.m_is_blockchain_synchronized);
}
