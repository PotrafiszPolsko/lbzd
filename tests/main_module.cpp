#include <gtest/gtest.h>
#include "../src/main_module.hpp"
#include "blockchain_module_mock.hpp"
#include "p2p_module_mock.hpp"
#include "main_module_mock_builder.hpp"
#include "../src/serialization_utils.hpp"
#include "../src/txid_generate.hpp"

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
	txs.at(0).m_vout.at(0).m_amount = 0;
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
	using ::testing::Return;
	EXPECT_CALL(bc_module, is_blockchain_synchronized())
			.WillOnce(Return(true));
	EXPECT_CALL(bc_module, block_exists(actual_hash))
			.WillOnce(Return(false));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_add_new_block request;
	request.m_block = block;
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
	txs.at(0).m_vout.at(0).m_amount = 0;
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

	using ::testing::_;
	EXPECT_CALL(pp_module, broadcast_transaction(_,_))
	        .WillOnce(
	            [&tx](const c_transaction & tx_tmp, const bool only_tor=true) {
		return tx == tx_tmp && only_tor;
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
	tx.m_vout.at(0).m_amount = 0;
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
	txs.at(0).m_vout.at(0).m_amount = 0;
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
	txs.at(0).m_vout.at(0).m_amount = 0;
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
	tx.m_vout.at(0).m_amount = 0;
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

TEST(main_module, get_voter_auth_data) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_public_key_type co_color;
	const std::string co_color_str = "fec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24";
	if(co_color_str.size()!=co_color.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(co_color.data(), co_color.size(),
						co_color_str.data(), co_color_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	c_transaction tx;
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_vin.resize(1);;
	tx.m_vout.resize(1);
	const std::string tx_allmetadata_str = "434ffec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24414C00000003504Bc2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
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
	tx.m_vout.at(0).m_amount = 1;
	tx.m_vout.at(0).m_pkh = generate_hash(voter_pk);
	std::vector<c_transaction> txs;
	txs.push_back(tx);

	std::map<t_public_key_type, uint32_t> auth_level;
	auth_level.emplace(std::make_pair(co_color, 3));

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_voter_auth_tx(voter_pk))
	        .WillOnce(Return(txs));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_voter_auth_data request;
	request.m_pk_voter = voter_pk;
	const auto response = main_module->notify(request);
	const auto &response_voter_auth_data = dynamic_cast<const t_mediator_command_response_get_voter_auth_data&>(*response);
	EXPECT_EQ(auth_level, response_voter_auth_data.m_auth_level);
}

TEST(main_module, get_personal_data) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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

	const bool is_voter_pk = true;
	using ::testing::Return;
	EXPECT_CALL(bc_module, is_pk_voter(voter_pk))
	        .WillOnce(Return(is_voter_pk));
	EXPECT_CALL(bc_module, get_hash_personal_data(voter_pk))
	        .WillOnce(Return(hash_data));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_personal_data request;
	request.m_pk_voter = voter_pk;
	const auto response = main_module->notify(request);
	const auto &response_get_personal_data = dynamic_cast<const t_mediator_command_response_get_personal_data&>(*response);
	EXPECT_EQ(hash_data, response_get_personal_data.m_hash_personal_data);
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

TEST(main_module, get_voting_results) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const std::string organizer_pk_str = "fec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24";
	t_public_key_type organizer_pk;
	int ret = 1;
	if(organizer_pk_str.size()!=organizer_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(organizer_pk.data(), organizer_pk.size(),
						organizer_pk_str.data(), organizer_pk_str.size(),
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

	std::string tx_str;
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

		nlohmann::json tx_json;
		tx_json = tx_create_voting;
		tx_str = tx_json.dump();
	}
	
	
	nlohmann::json tx_json;
	c_transaction tx;
	tx = tx_json.parse(tx_str);
	const t_hash_type option_hash_A = c_blockchain_module::get_vote_option_hash(tx, container_to_vector_of_uchars(voting_metadata.m_options.at(0)));
	const t_hash_type option_hash_B = c_blockchain_module::get_vote_option_hash(tx, container_to_vector_of_uchars(voting_metadata.m_options.at(1)));
	const size_t number_of_authorized_voters = 100;
	const uint32_t amount_option_A = 45;
	const uint32_t amount_option_B = 55;
	using ::testing::Return;
	EXPECT_CALL(bc_module, get_transaction(tx.m_txid))
	        .WillOnce(Return(tx));
//	EXPECT_CALL(bc_module, get_vote_option_hash(tx, container_to_vector_of_uchars(voting_metadata.m_options.at(0))))
//	        .WillOnce(Return(option_hash_A));
	EXPECT_CALL(bc_module, get_amount_pkh(option_hash_A))
	        .WillOnce(Return(amount_option_A));
//	EXPECT_CALL(bc_module, get_vote_option_hash(tx, container_to_vector_of_uchars(voting_metadata.m_options.at(1))))
//	        .WillOnce(Return(option_hash_B));
	EXPECT_CALL(bc_module, get_amount_pkh(option_hash_B))
	        .WillOnce(Return(amount_option_B));
	EXPECT_CALL(bc_module, get_number_of_all_voters_in_group(organizer_pk))
	        .WillOnce(Return(number_of_authorized_voters));
	
	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_voting_results request;
	request.m_txid_create_voting = tx.m_txid;
	const auto response = main_module->notify(request);
	const auto &response_get_voting_results = dynamic_cast<const t_mediator_command_response_get_voting_results&>(*response);
	EXPECT_EQ(voting_metadata.m_question, response_get_voting_results.m_question);
	EXPECT_EQ(voting_metadata.m_name, response_get_voting_results.m_voting_name);
	EXPECT_EQ(number_of_authorized_voters, response_get_voting_results.m_number_of_authorized_voters);
	EXPECT_EQ(amount_option_A, response_get_voting_results.m_voting_results.find(voting_metadata.m_options.at(0))->second);
	EXPECT_EQ(amount_option_B, response_get_voting_results.m_voting_results.find(voting_metadata.m_options.at(1))->second);
}

TEST(main_module, is_authorized_not_adminsys) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const std::string pk_str = "fec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24";
	t_public_key_type pk;
	int ret = 1;
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(pk.data(), pk.size(),
						pk_str.data(), pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_authorization_data auth_data;
	auth_data.m_type_of_transaction = t_transactiontype::authorize_issuer;
	t_public_key_type co_color;
	const std::string co_color_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(co_color_str.size()!=co_color.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(co_color.data(), co_color.size(),
						co_color_str.data(), co_color_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	auth_data.m_voting_group = co_color;
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	t_hash_type txid;
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	auth_data.m_txid = txid;
	std::vector<t_authorization_data> auths_data;
	auths_data.push_back(auth_data);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_authorization_data(pk))
	        .WillRepeatedly(Return(auths_data));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_authorized request;
	request.m_pk = pk;
	const auto response = main_module->notify(request);
	const auto &response_is_authorized = dynamic_cast<const t_mediator_command_response_is_authorized&>(*response);
	EXPECT_FALSE(response_is_authorized.m_is_adminsys);
	EXPECT_EQ(auth_data.m_txid, response_is_authorized.m_auth_data.at(0).m_txid);
	EXPECT_EQ(auth_data.m_type_of_transaction, response_is_authorized.m_auth_data.at(0).m_type_of_transaction);
	EXPECT_EQ(auth_data.m_voting_group, response_is_authorized.m_auth_data.at(0).m_voting_group);
}

TEST(main_module, is_authorized_adminsys) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_is_authorized request;
	request.m_pk = n_blockchainparams::admins_sys_pub_keys.at(0);
	const auto response = main_module->notify(request);
	const auto &response_is_authorized = dynamic_cast<const t_mediator_command_response_is_authorized&>(*response);
	EXPECT_TRUE(response_is_authorized.m_is_adminsys);
}

TEST(main_module, get_all_active_votings_for_voter) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
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
	t_hash_type voting_id;
	const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
						voting_id_str.data(), voting_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<std::pair<t_hash_type, t_voting_metadata>> active_votings;
	active_votings.push_back(std::make_pair(voting_id, voting_metadata));

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_active_votings_for_voter(voter_pk))
	        .WillRepeatedly(Return(active_votings));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_all_active_votings_for_voter request;
	request.m_voter_pk = voter_pk;
	const auto response = main_module->notify(request);
	const auto &response_get_all_active_votings_for_voter = dynamic_cast<const t_mediator_command_response_get_all_active_votings_for_voter&>(*response);
	EXPECT_EQ(active_votings.at(0), response_get_all_active_votings_for_voter.m_active_votings.at(0));	
}

TEST(main_module, get_amount_on_pkh) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_hash_type option_hash;
	const std::string option_hash_str = "d4debcb364a14025b13640899929abc31484797e4b6eaf788fba6833ec6fcc92";
	if(option_hash_str.size()!=option_hash.size()*2) throw std::invalid_argument("Bad option_hash size");
	const auto ret = sodium_hex2bin(option_hash.data(), option_hash.size(),
						option_hash_str.data(), option_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const uint32_t amount_option = 45;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_amount_pkh(option_hash))
	        .WillOnce(Return(amount_option));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_amount_on_pkh request;
	request.m_pkh = option_hash;
	const auto response = main_module->notify(request);
	const auto &response_get_amount = dynamic_cast<const t_mediator_command_response_get_amount_on_pkh&>(*response);
	EXPECT_EQ(amount_option, response_get_amount.m_amount);
}

TEST(main_module, check_voter_voted) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_hash_type voting_id;
	const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
						voting_id_str.data(), voting_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	bool is_voter_voted = true;
	using ::testing::Return;
	EXPECT_CALL(bc_module, check_the_voter_voted(voter_pk, voting_id))
	        .WillOnce(Return(is_voter_voted));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_check_voter_voted request;
	request.m_voter_pk = voter_pk;
	request.m_voting_id = voting_id;
	const auto response = main_module->notify(request);
	const auto &response_check_voter_voted = dynamic_cast<const t_mediator_command_response_check_voter_voted&>(*response);
	EXPECT_TRUE(response_check_voter_voted.m_voter_voted);
}

TEST(main_module, get_voter_auth_txid_for_voting) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_hash_type voting_id;
	const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
						voting_id_str.data(), voting_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
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
	EXPECT_CALL(bc_module, get_voter_auth_txid_for_voting(voter_pk, voting_id))
	        .WillOnce(Return(txid));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_voter_auth_txid_for_voting request;
	request.m_voter_pk = voter_pk;
	request.m_voting_id = voting_id;
	const auto response = main_module->notify(request);
	const auto &response_get_voter_auth_txid_for_voting = dynamic_cast<const t_mediator_command_response_get_voter_auth_txid_for_voting&>(*response);
	EXPECT_EQ(txid, response_get_voter_auth_txid_for_voting.m_txid);
}

TEST(main_module, get_voting_details) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_hash_type voting_id;
	const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
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

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_voting_details(voting_id))
	        .WillOnce(Return(voting_metadata));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_voting_details request;
	request.m_voting_id = voting_id;
	const auto response = main_module->notify(request);
	const auto &response_get_voting_details = dynamic_cast<const t_mediator_command_response_get_voting_details&>(*response);
	EXPECT_EQ(voting_metadata, response_get_voting_details.m_voting_details);
}

TEST(main_module, get_source_txid_for_pkh) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);

	t_hash_type pkh;
	const std::string pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
	int ret = 1;
	ret = sodium_hex2bin(pkh.data(), pkh.size(),
						pkh_str.data(), pkh_str.size(),
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
	EXPECT_CALL(bc_module, get_source_txid(pkh))
	        .WillOnce(Return(txid));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_source_txid_for_pkh request;
	request.m_pkh = pkh;
	const auto response = main_module->notify(request);
	const auto &response_get_source_txid_for_pkh = dynamic_cast<const t_mediator_command_response_get_source_txid_for_pkh&>(*response);
	EXPECT_EQ(txid, response_get_source_txid_for_pkh.m_txid);
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
	txs.at(0).m_vout.at(0).m_amount = 0;
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

TEST(main_module, get_all_vote_transactions) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	t_hash_type voting_id;
	const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	int ret = 1;
	ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
						voting_id_str.data(), voting_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	c_transaction tx;
	tx.m_vin.resize(1);;
	tx.m_vout.resize(1);
	const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
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
	tx.m_type = t_transactiontype::add_open_vote;
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
	const std::string tx_vin_txid_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
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
	std::vector<c_transaction> txs;
	txs.push_back(tx);
	using ::testing::Return;

	EXPECT_CALL(bc_module, get_all_vote_transactions(voting_id))
	        .WillOnce(Return(txs));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_all_vote_transactions request;
	request.m_voting_id = voting_id;
	const auto response = main_module->notify(request);
	const auto &response_get_all_vote_transactions = dynamic_cast<const t_mediator_command_response_get_all_vote_transactions&>(*response);
	EXPECT_EQ(txs, response_get_all_vote_transactions.m_vote_transactions);
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

TEST(main_module, get_voter_groups) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	t_public_key_type co_color;
	const std::string co_color_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(co_color_str.size()!=co_color.size()*2) throw std::invalid_argument("Bad co_color size");
	int ret = 1;
	ret = sodium_hex2bin(co_color.data(), co_color.size(),
						co_color_str.data(), co_color_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_public_key_type voter_pk;
	const std::string voter_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(voter_pk_str.size()!=voter_pk.size()*2) throw std::invalid_argument("Bad pk size");
	ret = sodium_hex2bin(voter_pk.data(), voter_pk.size(),
						voter_pk_str.data(), voter_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<t_public_key_type> voter_groups;
	voter_groups.push_back(co_color);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_voter_groups(voter_pk))
	        .WillOnce(Return(voter_groups));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_voter_groups request;
	request.m_voter_pk = voter_pk;
	const auto response = main_module->notify(request);
	const auto &response_get_voter_groups = dynamic_cast<const t_mediator_command_response_get_voter_groups&>(*response);
	EXPECT_EQ(voter_groups, response_get_voter_groups.m_voter_groups);
}

TEST(main_module, get_number_of_all_voters) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t number_of_all_voters = 1254;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_number_of_all_voters())
	        .WillOnce(Return(number_of_all_voters));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_all_voters request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_of_all_voters = dynamic_cast<const t_mediator_command_response_get_number_of_all_voters&>(*response);
	EXPECT_EQ(number_of_all_voters, response_get_number_of_all_voters.m_number_of_all_voters);
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

TEST(main_module, get_all_active_voting_ids) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	std::vector<std::pair<t_hash_type, t_voting_metadata>> active_votings;
	active_votings.push_back(std::make_pair(voting_id, voting_metadata));

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_active_votings())
	        .WillOnce(Return(active_votings));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_all_active_voting_ids request;
	const auto response = main_module->notify(request);
	const auto &response_get_all_active_votings_ids = dynamic_cast<const t_mediator_command_response_get_all_active_voting_ids&>(*response);
	std::vector<t_hash_type> voting_id_vec;
	voting_id_vec.push_back(voting_id);
	EXPECT_EQ(voting_id_vec, response_get_all_active_votings_ids.m_voting_ids);
}

TEST(main_module, get_number_of_all_votings) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	std::vector<std::pair<t_hash_type, t_voting_metadata>> active_votings;
	active_votings.push_back(std::make_pair(voting_id, voting_metadata));

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_votings())
	        .WillOnce(Return(active_votings));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_all_votings request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_of_all_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_votings&>(*response);
	EXPECT_EQ(active_votings.size(), response_get_number_of_all_votings.m_number_of_all_votings);
}

TEST(main_module, get_number_of_all_inactive_votings) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
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
	std::vector<std::pair<t_hash_type, t_voting_metadata>> inactive_votings;
	inactive_votings.push_back(std::make_pair(voting_id, voting_metadata));

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_inactive_votings())
	        .WillOnce(Return(inactive_votings));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_all_inactive_votings request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_of_all_inactive_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_inactive_votings&>(*response);
	EXPECT_EQ(inactive_votings.size(), response_get_number_of_all_inactive_votings.m_number_of_all_inactive_votings);
}

TEST(main_module, get_number_of_all_added_votes) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t number_of_all_added_votes = 1304;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_added_votes())
	        .WillOnce(Return(number_of_all_added_votes));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_all_added_votes request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_of_all_added_votes = dynamic_cast<const t_mediator_command_response_get_number_of_all_added_votes&>(*response);
	EXPECT_EQ(number_of_all_added_votes, response_get_number_of_all_added_votes.m_number_of_all_added_votes);
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

TEST(main_module, get_last_5_blocks) {
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

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_last_5_blocks())
	        .WillOnce(Return(blocks_record));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_last_5_blocks request;
	const auto response = main_module->notify(request);
	const auto &response_get_last_5_blocks = dynamic_cast<const t_mediator_command_response_get_last_5_blocks&>(*response);
	EXPECT_EQ(blocks_record, response_get_last_5_blocks.m_last_5_blocks);
}

TEST(main_module, get_last_5_transactions) {
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
	EXPECT_CALL(bc_module, get_last_5_transactions())
	        .WillOnce(Return(txs));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_last_5_transactions request;
	const auto response = main_module->notify(request);
	const auto &response_get_last_5_transactions = dynamic_cast<const t_mediator_command_response_get_last_5_transactions&>(*response);
	EXPECT_EQ(txs, response_get_last_5_transactions.m_last_5_transactions);
}

TEST(main_module, get_last_5_votings) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	std::vector<std::pair<t_hash_type, bool>> active_or_finished_votings;
	std::vector<std::pair<t_hash_type, double>> voter_turnout_votings;
	std::vector<t_hash_type> waiting_votings;
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
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
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679184050;
		const uint32_t voting_end_time = 1679191050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting C";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option Z", "option W"};
		voting_metadata.m_question = "Do you prefer option z or w?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 98));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "bbefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679185050;
		const uint32_t voting_end_time = 1679192050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting B";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option X", "option Y"};
		voting_metadata.m_question = "Do you prefer option x or y?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100078));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ccefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679186050;
		const uint32_t voting_end_time = 1679193050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting A";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option T", "option U"};
		voting_metadata.m_question = "Do you prefer option t or u?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 1789));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679187050;
		const uint32_t voting_end_time = 1679194050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting E";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option R", "option S"};
		voting_metadata.m_question = "Do you prefer option r or s?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		waiting_votings.push_back(voting_id);
		voter_turnout_votings.push_back(std::make_pair(voting_id, 0));
	}

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_last_5_votings())
	        .WillOnce(Return(votings));
	EXPECT_CALL(bc_module, finished_or_active_votings(votings))
	        .WillOnce(Return(active_or_finished_votings));
	EXPECT_CALL(bc_module, get_waiting_votings_ids(votings))
	        .WillOnce(Return(waiting_votings));
	EXPECT_CALL(bc_module, get_voter_turnout_from_specific_votes(votings))
	        .WillOnce(Return(voter_turnout_votings));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_last_5_votings request;
	const auto response = main_module->notify(request);
	const auto &response_get_last_5_votings = dynamic_cast<const t_mediator_command_response_get_last_5_votings&>(*response);
	EXPECT_EQ(votings, response_get_last_5_votings.m_last_5_votings);
	EXPECT_EQ(active_or_finished_votings, response_get_last_5_votings.m_is_finished);
	EXPECT_EQ(waiting_votings, response_get_last_5_votings.m_is_waiting);
	EXPECT_EQ(voter_turnout_votings, response_get_last_5_votings.m_voter_turnout);
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
	txs.at(0).m_vout.at(0).m_amount = 0;
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
	txs.at(0).m_vout.at(0).m_amount = 0;
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
	txs.at(0).m_vout.at(0).m_amount = 0;
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

TEST(main_module, get_votings_by_name_or_id_by_name) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	std::vector<std::pair<t_hash_type, bool>> active_or_finished_votings;
	std::vector<std::pair<t_hash_type, double>> voter_turnout_votings;
	std::vector<t_hash_type> waiting_votings;
	std::vector<std::pair<t_hash_type, std::unordered_map<std::string, uint32_t>> > votings_results;
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679183050;
		const uint32_t voting_end_time = 1679189050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option A", "option B"};
		voting_metadata.m_question = "Do you prefer option a or b?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100));
		std::unordered_map<std::string, uint32_t> options_result;
		options_result.emplace("option A", 30);
		options_result.emplace("option B", 70);
		votings_results.push_back(std::make_pair(voting_id, options_result));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679184050;
		const uint32_t voting_end_time = 1679191050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option Z", "option W"};
		voting_metadata.m_question = "Do you prefer option z or w?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 98));
		std::unordered_map<std::string, uint32_t> options_result;
		options_result.emplace("option Z", 45);
		options_result.emplace("option W", 53);
		votings_results.push_back(std::make_pair(voting_id, options_result));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "bbefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679185050;
		const uint32_t voting_end_time = 1679192050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option X", "option Y"};
		voting_metadata.m_question = "Do you prefer option x or y?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100078));
		std::unordered_map<std::string, uint32_t> options_result;
		options_result.emplace("option X", 100000);
		options_result.emplace("option Y", 78);
		votings_results.push_back(std::make_pair(voting_id, options_result));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ccefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679186050;
		const uint32_t voting_end_time = 1679193050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option T", "option U"};
		voting_metadata.m_question = "Do you prefer option t or u?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 1789));
		std::unordered_map<std::string, uint32_t> options_result;
		options_result.emplace("option T", 688);
		options_result.emplace("option U", 1101);
		votings_results.push_back(std::make_pair(voting_id, options_result));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679187050;
		const uint32_t voting_end_time = 1679194050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option R", "option S"};
		voting_metadata.m_question = "Do you prefer option r or s?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		waiting_votings.push_back(voting_id);
		voter_turnout_votings.push_back(std::make_pair(voting_id, 0));
		std::unordered_map<std::string, uint32_t> options_result;
		options_result.emplace("option R", 0);
		options_result.emplace("option S", 0);
		votings_results.push_back(std::make_pair(voting_id, options_result));
	}
	const size_t offset = 1;
	const std::string name = "Voting";
	const size_t number_of_all_votings_by_the_same_name = 5;
	const auto votings_with_number_of_all_votings_by_the_same_name = std::make_pair(votings, number_of_all_votings_by_the_same_name);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_votings_by_name_or_voting_id_with_number_votings(offset, name))
	        .WillOnce(Return(votings_with_number_of_all_votings_by_the_same_name));
	EXPECT_CALL(bc_module, finished_or_active_votings(votings))
	        .WillOnce(Return(active_or_finished_votings));
	EXPECT_CALL(bc_module, get_waiting_votings_ids(votings))
	        .WillOnce(Return(waiting_votings));
	EXPECT_CALL(bc_module, get_voter_turnout_from_specific_votes(votings))
	        .WillOnce(Return(voter_turnout_votings));
	EXPECT_CALL(bc_module, get_votings_results_from_specific_votes(votings))
	        .WillOnce(Return(votings_results));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_votings_by_name_or_id request;
	request.m_name_or_voting_id = "Voting";
	request.m_offset = 1;
	const auto response = main_module->notify(request);
	const auto &response_get_votings_by_name = dynamic_cast<const t_mediator_command_response_get_votings_by_name_or_id&>(*response);
	EXPECT_EQ(votings, response_get_votings_by_name.m_votings);
	EXPECT_EQ(active_or_finished_votings, response_get_votings_by_name.m_is_finished);
	EXPECT_EQ(waiting_votings, response_get_votings_by_name.m_is_waiting);
	EXPECT_EQ(voter_turnout_votings, response_get_votings_by_name.m_voter_turnout);
	EXPECT_EQ(votings_results, response_get_votings_by_name.m_votings_results);
	EXPECT_EQ(number_of_all_votings_by_the_same_name, response_get_votings_by_name.m_total_number_votings);
}

TEST(main_module, get_votings_by_name_or_id_by_voting_id) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	std::vector<std::pair<t_hash_type, bool>> active_or_finished_votings;
	std::vector<std::pair<t_hash_type, double>> voter_turnout_votings;
	std::vector<t_hash_type> waiting_votings;
	std::vector<std::pair<t_hash_type, std::unordered_map<std::string, uint32_t>> > votings_results;
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679187050;
		const uint32_t voting_end_time = 1679194050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option R", "option S"};
		voting_metadata.m_question = "Do you prefer option r or s?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		waiting_votings.push_back(voting_id);
		voter_turnout_votings.push_back(std::make_pair(voting_id, 0));
		std::unordered_map<std::string, uint32_t> options_result;
		options_result.emplace("option R", 0);
		options_result.emplace("option S", 0);
		votings_results.push_back(std::make_pair(voting_id, options_result));
	}
	const size_t offset = 1;
	const std::string voting_id = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	const size_t number_of_all_votings_by_the_same_name = 1;
	const auto votings_with_number_of_all_votings_by_the_same_name = std::make_pair(votings, number_of_all_votings_by_the_same_name);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_votings_by_name_or_voting_id_with_number_votings(offset, voting_id))
	        .WillOnce(Return(votings_with_number_of_all_votings_by_the_same_name));
	EXPECT_CALL(bc_module, finished_or_active_votings(votings))
	        .WillOnce(Return(active_or_finished_votings));
	EXPECT_CALL(bc_module, get_waiting_votings_ids(votings))
	        .WillOnce(Return(waiting_votings));
	EXPECT_CALL(bc_module, get_voter_turnout_from_specific_votes(votings))
	        .WillOnce(Return(voter_turnout_votings));
	EXPECT_CALL(bc_module, get_votings_results_from_specific_votes(votings))
	        .WillOnce(Return(votings_results));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_votings_by_name_or_id request;
	request.m_name_or_voting_id = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	request.m_offset = 1;
	const auto response = main_module->notify(request);
	const auto &response_get_votings_by_name = dynamic_cast<const t_mediator_command_response_get_votings_by_name_or_id&>(*response);
	EXPECT_EQ(votings, response_get_votings_by_name.m_votings);
	EXPECT_EQ(active_or_finished_votings, response_get_votings_by_name.m_is_finished);
	EXPECT_EQ(waiting_votings, response_get_votings_by_name.m_is_waiting);
	EXPECT_EQ(voter_turnout_votings, response_get_votings_by_name.m_voter_turnout);
	EXPECT_EQ(votings_results, response_get_votings_by_name.m_votings_results);
	EXPECT_EQ(number_of_all_votings_by_the_same_name, response_get_votings_by_name.m_total_number_votings);
}

TEST(main_module, get_latest_votings) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	std::vector<std::pair<t_hash_type, bool>> active_or_finished_votings;
	std::vector<std::pair<t_hash_type, double>> voter_turnout_votings;
	std::vector<t_hash_type> waiting_votings;
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
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
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679184050;
		const uint32_t voting_end_time = 1679191050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting C";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option Z", "option W"};
		voting_metadata.m_question = "Do you prefer option z or w?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 98));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "bbefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679185050;
		const uint32_t voting_end_time = 1679192050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting B";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option X", "option Y"};
		voting_metadata.m_question = "Do you prefer option x or y?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100078));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ccefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679186050;
		const uint32_t voting_end_time = 1679193050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting A";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option T", "option U"};
		voting_metadata.m_question = "Do you prefer option t or u?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 1789));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679187050;
		const uint32_t voting_end_time = 1679194050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting E";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option R", "option S"};
		voting_metadata.m_question = "Do you prefer option r or s?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		waiting_votings.push_back(voting_id);
		voter_turnout_votings.push_back(std::make_pair(voting_id, 0));
	}
	const size_t amount_votings = 5;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_latest_votings(amount_votings))
	        .WillOnce(Return(votings));
	EXPECT_CALL(bc_module, finished_or_active_votings(votings))
	        .WillOnce(Return(active_or_finished_votings));
	EXPECT_CALL(bc_module, get_waiting_votings_ids(votings))
	        .WillOnce(Return(waiting_votings));
	EXPECT_CALL(bc_module, get_voter_turnout_from_specific_votes(votings))
	        .WillOnce(Return(voter_turnout_votings));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_latest_votings request;
	request.m_amount_votings = amount_votings;
	const auto response = main_module->notify(request);
	const auto &response_get_latest_votings = dynamic_cast<const t_mediator_command_response_get_latest_votings&>(*response);
	EXPECT_EQ(votings, response_get_latest_votings.m_latest_votings);
	EXPECT_EQ(active_or_finished_votings, response_get_latest_votings.m_is_finished);
	EXPECT_EQ(waiting_votings, response_get_latest_votings.m_is_waiting);
	EXPECT_EQ(voter_turnout_votings, response_get_latest_votings.m_voter_turnout);
}

TEST(main_module, get_votings_per_page) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings;
	std::vector<std::pair<t_hash_type, bool>> active_or_finished_votings;
	std::vector<std::pair<t_hash_type, double>> voter_turnout_votings;
	std::vector<t_hash_type> waiting_votings;
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
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
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679184050;
		const uint32_t voting_end_time = 1679191050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting C";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option Z", "option W"};
		voting_metadata.m_question = "Do you prefer option z or w?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 98));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "bbefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679185050;
		const uint32_t voting_end_time = 1679192050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting B";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option X", "option Y"};
		voting_metadata.m_question = "Do you prefer option x or y?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 100078));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ccefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679186050;
		const uint32_t voting_end_time = 1679193050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting A";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option T", "option U"};
		voting_metadata.m_question = "Do you prefer option t or u?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		active_or_finished_votings.push_back(std::make_pair(voting_id, true));
		voter_turnout_votings.push_back(std::make_pair(voting_id, 1789));
	}
	{
		t_hash_type voting_id;
		const std::string voting_id_str = "ddefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
		if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
		const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
							voting_id_str.data(), voting_id_str.size(),
							nullptr, nullptr, nullptr);
		if (ret!=0) throw std::runtime_error("hex2bin error");
		t_voting_metadata voting_metadata;
		voting_metadata.m_start_timepoint = 1679187050;
		const uint32_t voting_end_time = 1679194050;
		const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
		const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
		voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
		voting_metadata.m_name = "Voting E";
		voting_metadata.m_voting_type = 0;
		voting_metadata.m_authorization_level = 1;
		voting_metadata.m_number_of_choice = 1;
		voting_metadata.m_options = {"option R", "option S"};
		voting_metadata.m_question = "Do you prefer option r or s?";
		votings.push_back(std::make_pair(voting_id, voting_metadata));
		waiting_votings.push_back(voting_id);
		voter_turnout_votings.push_back(std::make_pair(voting_id, 0));
	}
	const size_t total_number_votings = 5;
	const auto votings_with_total_number_votings = std::make_pair(votings, total_number_votings);
	const size_t offset = 1;

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_votings_per_page(offset))
	        .WillOnce(Return(votings_with_total_number_votings));
	EXPECT_CALL(bc_module, finished_or_active_votings(votings))
	        .WillOnce(Return(active_or_finished_votings));
	EXPECT_CALL(bc_module, get_waiting_votings_ids(votings))
	        .WillOnce(Return(waiting_votings));
	EXPECT_CALL(bc_module, get_voter_turnout_from_specific_votes(votings))
	        .WillOnce(Return(voter_turnout_votings));

	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_votings_per_page request;
	request.m_offset = offset;
	const auto response = main_module->notify(request);
	const auto &response_get_votings_per_page = dynamic_cast<const t_mediator_command_response_get_votings_per_page&>(*response);
	EXPECT_EQ(votings, response_get_votings_per_page.m_votings);
	EXPECT_EQ(active_or_finished_votings, response_get_votings_per_page.m_is_finished);
	EXPECT_EQ(waiting_votings, response_get_votings_per_page.m_is_waiting);
	EXPECT_EQ(voter_turnout_votings, response_get_votings_per_page.m_voter_turnout);
	EXPECT_EQ(total_number_votings, response_get_votings_per_page.m_total_number_votings);
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

TEST(main_module, get_number_of_all_active_votings) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t number_active_votings = 10;
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings(number_active_votings);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_active_votings())
	        .WillOnce(Return(votings));
	
	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_all_active_votings request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_active_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_active_votings&>(*response);
	EXPECT_EQ(number_active_votings, response_get_number_active_votings.m_number_of_all_active_votings);
}

TEST(main_module, get_number_of_all_finished_votings) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	const size_t number_finished_votings = 10;
	std::vector<std::pair<t_hash_type, t_voting_metadata>> votings(number_finished_votings);

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_all_finished_votings())
	        .WillOnce(Return(votings));
	
	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_number_of_all_finished_votings request;
	const auto response = main_module->notify(request);
	const auto &response_get_number_finished_votings = dynamic_cast<const t_mediator_command_response_get_number_of_all_finished_votings&>(*response);
	EXPECT_EQ(number_finished_votings, response_get_number_finished_votings.m_number_of_all_finished_votings);
}

TEST(main_module, get_voting_by_id) {
	std::unique_ptr<c_blockchain_module> blockchain_module = std::make_unique<c_blockchain_module_mock>();
	c_blockchain_module_mock &bc_module = dynamic_cast<c_blockchain_module_mock&>(*blockchain_module);
	t_hash_type voting_id;
	const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
	const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
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
	const size_t voter_turnout = 100;
	std::unordered_map<std::string, uint32_t> voting_results;
	voting_results.emplace("option A", 10);
	voting_results.emplace("option B", 90);
	const unsigned char voting_status = 'X';

	using ::testing::Return;
	EXPECT_CALL(bc_module, get_voting_details(voting_id))
	        .WillOnce(Return(voting_metadata));
	EXPECT_CALL(bc_module, get_voter_turnout_from_vote(voting_id))
	        .WillOnce(Return(voter_turnout));
	EXPECT_CALL(bc_module, get_voting_result(voting_id))
	        .WillOnce(Return(voting_results));
	EXPECT_CALL(bc_module, get_voting_status(voting_id))
	        .WillOnce(Return(voting_status));
	
	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_blockchain_module(std::move(blockchain_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_voting_by_id request;
	request.m_voting_id = voting_id;
	const auto response = main_module->notify(request);
	const auto &response_get_voting_by_id = dynamic_cast<const t_mediator_command_response_get_voting_by_id&>(*response);
	EXPECT_EQ(voting_metadata, response_get_voting_by_id.m_voting_metadata);
	EXPECT_EQ(voter_turnout, response_get_voting_by_id.m_voter_turnout);
	EXPECT_EQ(voting_results.find("option A")->second, response_get_voting_by_id.m_voting_results.find("option A")->second);
	EXPECT_EQ(voting_results.find("option B")->second, response_get_voting_by_id.m_voting_results.find("option B")->second);
}

TEST(main_module, get_peers) {
	std::unique_ptr<c_p2p_module> p2p_module = std::make_unique<c_p2p_module_mock>();
	c_p2p_module_mock & pp_module = dynamic_cast<c_p2p_module_mock&>(*p2p_module);

	const std::string address_tcp_str = "91.236.233.26";
	const unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	const std::string address_tor_str = "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion";
	auto peer_ref_from_tor = create_peer_reference(address_tor_str, port);

	std::vector<std::unique_ptr<c_peer_reference> > peer_ref_vec_with_tcp;
	peer_ref_vec_with_tcp.push_back(std::move(peer_ref_from_tcp));
	std::vector<std::unique_ptr<c_peer_reference> > peer_ref_vec_with_tor;
	peer_ref_vec_with_tor.push_back(std::move(peer_ref_from_tor));

	EXPECT_CALL(pp_module, get_peers_tcp())
	        .WillOnce(
	            []() -> std::vector<std::unique_ptr<c_peer_reference> > {
	                const std::string address_tcp_str = "91.236.233.26";
					const unsigned short port = 22083;
					auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	                std::vector<std::unique_ptr<c_peer_reference> > peer_ref_vec_with_tcp;
					peer_ref_vec_with_tcp.push_back(std::move(peer_ref_from_tcp));
	                return peer_ref_vec_with_tcp;
	});

	EXPECT_CALL(pp_module, get_peers_tor())
	        .WillOnce(
	            []() -> std::vector<std::unique_ptr<c_peer_reference> > {
	                const std::string address_tor_str = "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion";
					const unsigned short port = 22083;
					auto peer_ref_from_tor = create_peer_reference(address_tor_str, port);
	                std::vector<std::unique_ptr<c_peer_reference> > peer_ref_vec_with_tor;
					peer_ref_vec_with_tor.push_back(std::move(peer_ref_from_tor));
	                return peer_ref_vec_with_tor;
	});
	
	c_main_module_mock_builder main_module_mock_builder;
	main_module_mock_builder.set_p2p_module(std::move(p2p_module));
	auto main_module = main_module_mock_builder.get_result();
	t_mediator_command_request_get_peers request;
	const auto response = main_module->notify(request);
	const auto &response_get_peers = dynamic_cast<const t_mediator_command_response_get_peers&>(*response);
	const auto peer_tcp = dynamic_cast<c_peer_reference_tcp&>(*response_get_peers.m_peers_tcp.at(0));
	const auto peer_tor = dynamic_cast<c_peer_reference_onion&>(*response_get_peers.m_peers_tor.at(0));
	EXPECT_EQ("91.236.233.26:22083", peer_tcp.to_string());
	EXPECT_EQ("jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion:22083", peer_tor.to_string());
}
