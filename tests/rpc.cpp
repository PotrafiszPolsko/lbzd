#include <gtest/gtest.h>
#include "mediator_mock.hpp"
#include "../src/rpc_exec.hpp"
#include "../src/rpc_module.hpp"
#include "../src/utils.hpp"

class c_rpc_server_test : public c_rpc_server_base {
	public:
		c_rpc_server_test(std::shared_ptr<c_rpc_exec> exec)
			:
			  c_rpc_server_base(exec) {}
		void run_and_block(){}
	};

class rpc : public ::testing::Test {
	protected:
		c_mediator_mock m_mediator_mock;
};

TEST_F(rpc, ping) {
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "ping";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], "pong");
}

TEST_F(rpc, get_block_by_hash) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
	            	const auto request_get_block_by_id = dynamic_cast<const t_mediator_command_request_get_block_by_id&>(request);
					response = std::make_unique<t_mediator_command_response_get_block_by_id>();
					auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_id&>(*response);
					t_hash_type actual_hash;
					const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
					if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
					int ret = 1;
					ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
										actual_hash_str.data(), actual_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_actual_hash = actual_hash;
					EXPECT_EQ(request_get_block_by_id.m_block_hash, actual_hash);
					std::vector<t_signature_type> all_signatures;
					all_signatures.resize(1);
					const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
					if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
					ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
										all_signatures_str.data(), all_signatures_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_signatures = all_signatures;
					t_hash_type all_tx_hash;
					const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
					ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
										all_tx_hash_str.data(), all_tx_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_tx_hash = all_tx_hash;
					response_get_block.m_block.m_header.m_block_time = 1679079676;
					t_hash_type parent_hash;
					const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
					if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
					ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
										parent_hash_str.data(), parent_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_parent_hash = parent_hash;
					response_get_block.m_block.m_header.m_version = 0;
					std::vector<c_transaction> txs;
					txs.resize(1);
					txs.at(0).m_vin.resize(1);
					txs.at(0).m_vout.resize(1);
					const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
					txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(tx_txid_str.size()!=txs.at(0).m_txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txs.at(0).m_txid.data(), txs.at(0).m_txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					txs.at(0).m_type = t_transactiontype::authorize_organizer;
					const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
					if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
					if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					if(tx_vin_txid_str.size()!=txs.at(0).m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_txid.data(), txs.at(0).m_vin.at(0).m_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					txs.at(0).m_vout.at(0).m_amount = 0;
					const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
					if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_transaction = txs;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_block_by_hash";
	cmd["params"]["hash"] = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["header"]["actual_hash"], "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe");
	EXPECT_EQ(result["result"]["data"]["header"]["all_signatures"].at(0), "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e");
	EXPECT_EQ(result["result"]["data"]["header"]["all_tx_hash"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["header"]["block_time"], 1679079676);
	EXPECT_EQ(result["result"]["data"]["header"]["parent_hash"], "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469");
	EXPECT_EQ(result["result"]["data"]["header"]["version"], 0);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["allmetadata"], "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["txid"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["type"], 4);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["pk"], "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["sign"], "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["amount"], 0);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["pkh"], "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3");
}

TEST_F(rpc, get_block_by_txid) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_block_by_txid = dynamic_cast<const t_mediator_command_request_get_block_by_txid&>(request);
					response = std::make_unique<t_mediator_command_response_get_block_by_txid>();
					auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_txid&>(*response);
					t_hash_type actual_hash;
					const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
					if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
					int ret = 1;
					ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
										actual_hash_str.data(), actual_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_actual_hash = actual_hash;
					std::vector<t_signature_type> all_signatures;
					all_signatures.resize(1);
					const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
					if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
					ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
										all_signatures_str.data(), all_signatures_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_signatures = all_signatures;
					t_hash_type all_tx_hash;
					const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
					ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
										all_tx_hash_str.data(), all_tx_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_tx_hash = all_tx_hash;
					response_get_block.m_block.m_header.m_block_time = 1679079676;
					t_hash_type parent_hash;
					const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
					if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
					ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
										parent_hash_str.data(), parent_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_parent_hash = parent_hash;
					response_get_block.m_block.m_header.m_version = 0;
					std::vector<c_transaction> txs;
					txs.resize(1);
					txs.at(0).m_vin.resize(1);
					txs.at(0).m_vout.resize(1);
					const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
					txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(tx_txid_str.size()!=txs.at(0).m_txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txs.at(0).m_txid.data(), txs.at(0).m_txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_block_by_txid.m_txid, txs.at(0).m_txid);
					txs.at(0).m_type = t_transactiontype::authorize_organizer;
					const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
					if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
					if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					if(tx_vin_txid_str.size()!=txs.at(0).m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_txid.data(), txs.at(0).m_vin.at(0).m_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					txs.at(0).m_vout.at(0).m_amount = 0;
					const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
					if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_transaction = txs;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_block_by_txid";
	cmd["params"]["txid"] = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["header"]["actual_hash"], "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe");
	EXPECT_EQ(result["result"]["data"]["header"]["all_signatures"].at(0), "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e");
	EXPECT_EQ(result["result"]["data"]["header"]["all_tx_hash"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["header"]["block_time"], 1679079676);
	EXPECT_EQ(result["result"]["data"]["header"]["parent_hash"], "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469");
	EXPECT_EQ(result["result"]["data"]["header"]["version"], 0);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["allmetadata"], "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["txid"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["type"], 4);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["pk"], "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["sign"], "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["amount"], 0);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["pkh"], "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3");
}

TEST_F(rpc, get_block_by_height) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_block_by_height = dynamic_cast<const t_mediator_command_request_get_block_by_height&>(request);
					EXPECT_EQ(request_get_block_by_height.m_height, 2);
					response = std::make_unique<t_mediator_command_response_get_block_by_height>();
					auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_height&>(*response);
					t_hash_type actual_hash;
					const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
					if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
					int ret = 1;
					ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
										actual_hash_str.data(), actual_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_actual_hash = actual_hash;
					std::vector<t_signature_type> all_signatures;
					all_signatures.resize(1);
					const std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
					if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
					ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
										all_signatures_str.data(), all_signatures_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_signatures = all_signatures;
					t_hash_type all_tx_hash;
					const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
					ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
										all_tx_hash_str.data(), all_tx_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_tx_hash = all_tx_hash;
					response_get_block.m_block.m_header.m_block_time = 1679079676;
					t_hash_type parent_hash;
					const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
					if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
					ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
										parent_hash_str.data(), parent_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_parent_hash = parent_hash;
					response_get_block.m_block.m_header.m_version = 0;
					std::vector<c_transaction> txs;
					txs.resize(1);
					txs.at(0).m_vin.resize(1);
					txs.at(0).m_vout.resize(1);
					const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
					txs.at(0).m_allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=txs.at(0).m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					ret = sodium_hex2bin(txs.at(0).m_allmetadata.data(), txs.at(0).m_allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(tx_txid_str.size()!=txs.at(0).m_txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txs.at(0).m_txid.data(), txs.at(0).m_txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					txs.at(0).m_type = t_transactiontype::authorize_organizer;
					const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
					if(tx_vin_pk_str.size()!=txs.at(0).m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_pk.data(), txs.at(0).m_vin.at(0).m_pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
					if(tx_vin_sign_str.size()!=txs.at(0).m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_sign.data(), txs.at(0).m_vin.at(0).m_sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					if(tx_vin_txid_str.size()!=txs.at(0).m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vin.at(0).m_txid.data(), txs.at(0).m_vin.at(0).m_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					txs.at(0).m_vout.at(0).m_amount = 0;
					const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
					if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size from tx");
					ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_transaction = txs;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_block_by_height";
	cmd["params"]["height"] = 2;
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["header"]["actual_hash"], "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe");
	EXPECT_EQ(result["result"]["data"]["header"]["all_signatures"].at(0), "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e");
	EXPECT_EQ(result["result"]["data"]["header"]["all_tx_hash"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["header"]["block_time"], 1679079676);
	EXPECT_EQ(result["result"]["data"]["header"]["parent_hash"], "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469");
	EXPECT_EQ(result["result"]["data"]["header"]["version"], 0);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["allmetadata"], "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["txid"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["type"], 4);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["pk"], "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["sign"], "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["amount"], 0);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["pkh"], "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3");
}

TEST_F(rpc, get_tx) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_tx = dynamic_cast<const t_mediator_command_request_get_tx&>(request);
					response = std::make_unique<t_mediator_command_response_get_tx>();
					auto & response_get_tx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
					const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
					std::vector<unsigned char> allmetadata;
					allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					int ret = 1;
					ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_allmetadata = allmetadata;
					const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					t_hash_type txid;
					if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_txid = txid;
					EXPECT_EQ(request_get_tx.m_txid, txid);
					response_get_tx.m_transaction.m_type = t_transactiontype::authorize_organizer;
					const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
					t_public_key_type pk;
					if(tx_vin_pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.resize(1);
					response_get_tx.m_transaction.m_vin.at(0).m_pk = pk;
					const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
					t_signature_type sign;
					if(tx_vin_sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(sign.data(), sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_sign = sign;
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					t_hash_type vin_txid;
					if(tx_vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_txid = vin_txid;
					response_get_tx.m_transaction.m_vout.resize(1);
					response_get_tx.m_transaction.m_vout.at(0).m_amount = 0;
					const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
					t_hash_type pkh;
					if(tx_vout_pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size from tx");
					ret = sodium_hex2bin(pkh.data(), pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vout.at(0).m_pkh = pkh;
					assert(response != nullptr);
					return response;
	});
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_tx";
	cmd["params"]["txid"] = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["allmetadata"], "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea");
	EXPECT_EQ(result["result"]["data"]["txid"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["type"], 4);
	EXPECT_EQ(result["result"]["data"]["vin"].at(0)["pk"], "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef");
	EXPECT_EQ(result["result"]["data"]["vin"].at(0)["sign"], "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305");
	EXPECT_EQ(result["result"]["data"]["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["vout"].at(0)["amount"], 0);
	EXPECT_EQ(result["result"]["data"]["vout"].at(0)["pkh"], "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3");
}

TEST_F(rpc, verify_pk_true) {
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "verify_pk";
	cmd["params"]["message"] = "test message";
	cmd["params"]["pk"] = "fe7b6a9aa0c1adbfb0ac60c17c99d0b0fec3eb0cd62307e8e65e7f8bb4df057c";
	cmd["params"]["sign"] = "bc86b52e1b6bb10e3c282ae603fef08cb88e5c982a748d2babc419a2c16aa6b3a2ee6ee933c3d7997c9d49408a43b7f1fd488ca43e964efa05cff92b79dc2309";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], true);
}

TEST_F(rpc, verify_pk_false) {
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "verify_pk";
	cmd["params"]["message"] = "test message";
	cmd["params"]["pk"] = "ee7b6a9aa0c1adbfb0ac60c17c99d0b0fec3eb0cd62307e8e65e7f8bb4df057c";
	cmd["params"]["sign"] = "bc86b52e1b6bb10e3c282ae603fef08cb88e5c982a748d2babc419a2c16aa6b3a2ee6ee933c3d7997c9d49408a43b7f1fd488ca43e964efa05cff92b79dc2309";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], false);
}

TEST_F(rpc, get_authorize_level_of_voter) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_voter_auth_data = dynamic_cast<const t_mediator_command_request_get_voter_auth_data&>(request);
					response = std::make_unique<t_mediator_command_response_get_voter_auth_data>();
					auto & response_get_voter_auth_data = dynamic_cast<t_mediator_command_response_get_voter_auth_data&>(*response);
					t_public_key_type pk;
					const std::string pk_str = "10aa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					int ret = 1;
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_voter_auth_data.m_pk_voter, pk);
					std::map<t_public_key_type, uint32_t> color_vec_auth_level;
					const std::string co_color_str = "14cd072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe193c91";
					t_public_key_type co_color;
					if(co_color_str.size()!=co_color.size()*2) throw std::invalid_argument("Bad co_color size");
					ret = sodium_hex2bin(co_color.data(), co_color.size(),
										co_color_str.data(), co_color_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					color_vec_auth_level.emplace(co_color, 3);
					response_get_voter_auth_data.m_auth_level = color_vec_auth_level;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_authorize_level_of_voter";
	cmd["params"]["pk"] = "10aa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["authorization_level"]["14cd072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe193c91"], 3);
}

TEST_F(rpc, get_personal_data) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_personal_data = dynamic_cast<const t_mediator_command_request_get_personal_data&>(request);
					response = std::make_unique<t_mediator_command_response_get_personal_data>();
					auto & response_get_personal_data = dynamic_cast<t_mediator_command_response_get_personal_data&>(*response);
					t_public_key_type pk;
					const std::string pk_str = "3bbd072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1939a7";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					int ret = 1;
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_personal_data.m_pk_voter, pk);
					t_hash_type hash_personal_data;
					const std::string hash_personal_data_str = "11fa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
					if(hash_personal_data_str.size()!=hash_personal_data.size()*2) throw std::invalid_argument("Bad hash size");
					ret = sodium_hex2bin(hash_personal_data.data(), hash_personal_data.size(),
										hash_personal_data_str.data(), hash_personal_data_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_personal_data.m_hash_personal_data = hash_personal_data;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_personal_data";
	cmd["params"]["pk_voter"] = "3bbd072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1939a7";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["hash_personal_data"], "11fa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc");
}

TEST_F(rpc, get_height) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_height>();
					auto & response_get_height = dynamic_cast<t_mediator_command_response_get_height&>(*response);
					response_get_height.m_height = 39;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_height";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["height"], 39);
}

TEST_F(rpc, voting_results) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_voting_results = dynamic_cast<const t_mediator_command_request_get_voting_results&>(request);
					response = std::make_unique<t_mediator_command_response_get_voting_results>();
					auto & response_get_voting_results = dynamic_cast<t_mediator_command_response_get_voting_results&>(*response);
					t_hash_type txid;
					const std::string txid_str = "d4debcb364a14025b13640899929abc31484797e4b6eaf788fba6833ec6fcc92";
					if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
					const auto ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_str.data(), txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_voting_results.m_txid_create_voting, txid);
					response_get_voting_results.m_voting_results.emplace("a", 43);
					response_get_voting_results.m_voting_results.emplace("b", 57);
					response_get_voting_results.m_number_of_authorized_voters = 100;
					response_get_voting_results.m_voting_name = "Voting 149";
					response_get_voting_results.m_question = "Do you prefer option a or b?";
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "voting_results";
	cmd["params"]["txid_create_voting"] = "d4debcb364a14025b13640899929abc31484797e4b6eaf788fba6833ec6fcc92";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["options"]["a"], 43);
	EXPECT_EQ(result["result"]["data"]["options"]["b"], 57);
	EXPECT_EQ(result["result"]["data"]["number_of_authorized_voters"], 100);
	EXPECT_EQ(result["result"]["data"]["voting_name"], "Voting 149");
	EXPECT_EQ(result["result"]["data"]["voting_question"], "Do you prefer option a or b?");
}

TEST_F(rpc, is_pk_authorized_voter_or_issuer_or_organizer_pk) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_is_authorized = dynamic_cast<const t_mediator_command_request_is_authorized&>(request);
					response = std::make_unique<t_mediator_command_response_is_authorized>();
					auto & response_is_authorized = dynamic_cast<t_mediator_command_response_is_authorized&>(*response);
					t_public_key_type pk;
					const std::string pk_str = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					int ret = 1;
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_is_authorized.m_pk, pk);
					response_is_authorized.m_auth_data.resize(1);
					t_hash_type txid;
					const std::string txid_str = "9284f1bab887876b0427b60f043ab957087bcd04e9940f216e90704568688deb";
					if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_str.data(), txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_is_authorized.m_auth_data.at(0).m_txid = txid;
					response_is_authorized.m_auth_data.at(0).m_type_of_transaction = t_transactiontype::authorize_voter;
					t_public_key_type voting_group;
					const std::string voting_group_str = "8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
					if(voting_group_str.size()!=voting_group.size()*2) throw std::invalid_argument("Bad voting group size");
					ret = sodium_hex2bin(voting_group.data(), voting_group.size(),
										voting_group_str.data(), voting_group_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_is_authorized.m_auth_data.at(0).m_voting_group = voting_group;
					response_is_authorized.m_is_adminsys = false;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "is_pk_authorized";
	cmd["params"]["pk"] = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["authorizations_data"].at(0)["txid"], "9284f1bab887876b0427b60f043ab957087bcd04e9940f216e90704568688deb");
	EXPECT_EQ(result["result"]["data"]["authorizations_data"].at(0)["type_of_authorized"], t_transactiontype::authorize_voter);
	EXPECT_EQ(result["result"]["data"]["authorizations_data"].at(0)["voting_group"], "8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea");
	EXPECT_NE(result["result"]["data"], "This public key is the adminsys public key");
	EXPECT_NE(result["result"]["data"], "This public key is not authorized");
}

TEST_F(rpc, is_pk_authorized_adminsys_pk) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_is_authorized = dynamic_cast<const t_mediator_command_request_is_authorized&>(request);
					response = std::make_unique<t_mediator_command_response_is_authorized>();
					auto & response_is_authorized = dynamic_cast<t_mediator_command_response_is_authorized&>(*response);
					t_public_key_type pk;
					const std::string pk_str = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					int ret = 1;
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_is_authorized.m_pk, pk);
					response_is_authorized.m_is_adminsys = true;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "is_pk_authorized";
	cmd["params"]["pk"] = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], "This public key is the adminsys public key");
	EXPECT_NE(result["result"]["data"], "This public key is not authorized");
}

TEST_F(rpc, is_pk_authorized_no_authorized_pk) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_is_authorized = dynamic_cast<const t_mediator_command_request_is_authorized&>(request);
					response = std::make_unique<t_mediator_command_response_is_authorized>();
					auto & response_is_authorized = dynamic_cast<t_mediator_command_response_is_authorized&>(*response);
					t_public_key_type pk;
					const std::string pk_str = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					int ret = 1;
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_is_authorized.m_pk, pk);
					response_is_authorized.m_is_adminsys = false;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "is_pk_authorized";
	cmd["params"]["pk"] = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], "This public key is not authorized");
	EXPECT_NE(result["result"]["data"], "This public key is the adminsys public key");
}

TEST_F(rpc, get_active_votings_for_voter) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_active_votings_for_voter = dynamic_cast<const t_mediator_command_request_get_all_active_votings_for_voter&>(request);
					response = std::make_unique<t_mediator_command_response_get_all_active_votings_for_voter>();
					auto & response_active_votings_for_voter = dynamic_cast<t_mediator_command_response_get_all_active_votings_for_voter&>(*response);
					t_public_key_type pk;
					const std::string pk_str = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					int ret = 1;
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_active_votings_for_voter.m_voter_pk, pk);
					response_active_votings_for_voter.m_active_votings.resize(1);
					response_active_votings_for_voter.m_active_votings.at(0).second.m_authorization_level = 1;
					response_active_votings_for_voter.m_active_votings.at(0).second.m_name = "Voting B";
					response_active_votings_for_voter.m_active_votings.at(0).second.m_number_of_choice = 1;
					response_active_votings_for_voter.m_active_votings.at(0).second.m_options.push_back("a");
					response_active_votings_for_voter.m_active_votings.at(0).second.m_options.push_back("b");
					response_active_votings_for_voter.m_active_votings.at(0).second.m_question = "Do you prefer option a or b?";
					const uint32_t voting_start_time = 1679078530;
					const uint32_t voting_end_time = 1679083030;
					const uint32_t voting_time = voting_end_time - voting_start_time;
					const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
					response_active_votings_for_voter.m_active_votings.at(0).second.m_number_of_blocks_to_the_end = number_of_blocks;
					t_hash_type txid;
					const std::string txid_str = "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
					if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_str.data(), txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_active_votings_for_voter.m_active_votings.at(0).first = txid;
					response_active_votings_for_voter.m_active_votings.at(0).second.m_start_timepoint = voting_start_time;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_active_votings_for_voter";
	cmd["params"]["voter_pk"] = "1bf234f239e88fc021e75cbeda75a11bae6a5c5943470d40502dfeefe00e883d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"].at(0)["authorization_level"], 1);
	EXPECT_EQ(result["result"]["data"].at(0)["name"], "Voting B");
	EXPECT_EQ(result["result"]["data"].at(0)["number_of_choice"], 1);
	const std::array<std::string,2> options = {"a", "b"};
	EXPECT_EQ(result["result"]["data"].at(0)["options"], options);
	EXPECT_EQ(result["result"]["data"].at(0)["question"], "Do you prefer option a or b?");
	EXPECT_EQ(result["result"]["data"].at(0)["voting_end_time"], 1679083030);
	EXPECT_EQ(result["result"]["data"].at(0)["voting_id"], "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	EXPECT_EQ(result["result"]["data"].at(0)["voting_start_time"], 1679078530);
}

TEST_F(rpc, get_voting_details) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_voting_details = dynamic_cast<const t_mediator_command_request_get_voting_details&>(request);
					response = std::make_unique<t_mediator_command_response_get_voting_details>();
					auto & response_get_voting_details = dynamic_cast<t_mediator_command_response_get_voting_details&>(*response);
					t_hash_type txid;
					const std::string txid_str = "c05effef46c30d73e54f15731faac9340a9e42ff929dbb5abee8efabb2dba255";
					if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
					int ret = 1;
					ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_str.data(), txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_voting_details.m_voting_id, txid);
					response_get_voting_details.m_voting_details.m_authorization_level = 1;
					response_get_voting_details.m_voting_details.m_name = "Voting 122";
					response_get_voting_details.m_voting_details.m_number_of_choice = 1;
					response_get_voting_details.m_voting_details.m_options.push_back("a");
					response_get_voting_details.m_voting_details.m_options.push_back("b");
					response_get_voting_details.m_voting_details.m_question = "Do you prefer option a or b?";
					const uint32_t voting_start_time = 1672310255;
					const uint32_t voting_end_time = 1672314755;
					const uint32_t voting_time = voting_end_time - voting_start_time;
					const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
					response_get_voting_details.m_voting_details.m_number_of_blocks_to_the_end = number_of_blocks;
					response_get_voting_details.m_voting_details.m_start_timepoint = voting_start_time;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_voting_details";
	cmd["params"]["voting_id"] = "c05effef46c30d73e54f15731faac9340a9e42ff929dbb5abee8efabb2dba255";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["authorization_level"], 1);
	EXPECT_EQ(result["result"]["data"]["name"], "Voting 122");
	EXPECT_EQ(result["result"]["data"]["number_of_choice"], 1);
	const std::array<std::string,2> options = {"a", "b"};
	EXPECT_EQ(result["result"]["data"]["options"], options);
	EXPECT_EQ(result["result"]["data"]["question"], "Do you prefer option a or b?");
	EXPECT_EQ(result["result"]["data"]["voting_end_time"], 1672314755);
	EXPECT_EQ(result["result"]["data"]["voting_start_time"], 1672310255);
}

TEST_F(rpc, get_peers) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_peers>();
					auto & response_get_peers = dynamic_cast<t_mediator_command_response_get_peers&>(*response);
					const std::string address_tcp_str = "91.236.233.26";
					boost::system::error_code ec;
					const auto ip = boost::asio::ip::make_address(address_tcp_str, ec);
					const unsigned short port = 22083;
					c_peer_reference_tcp tcp_peer(ip, port);
					response_get_peers.m_peers_tcp.push_back(std::make_unique<c_peer_reference_tcp>(tcp_peer));
					const std::string address_tor_str = "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion";
					c_peer_reference_onion tor_peer(address_tor_str, port);
					response_get_peers.m_peers_tor.push_back(std::make_unique<c_peer_reference_onion>(tor_peer));
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_peers";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["peers_tcp"].at(0), "91.236.233.26:22083");
	EXPECT_EQ(result["result"]["data"]["peers_tor"].at(0), "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion:22083");
}

TEST_F(rpc, get_transactions_from_mempool) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_mempool_transactions>();
					auto & response_get_transactions_from_mempool = dynamic_cast<t_mediator_command_response_get_mempool_transactions&>(*response);
					c_transaction tx;
					tx.m_vin.resize(1);
					tx.m_vout.resize(1);
					const std::string allmetadata_str = "5649beb99ecdd5d0ba5dc51ce2306f044fe2a97e94e2c1f732818258d6d8da417d6d";
					tx.m_allmetadata.resize(allmetadata_str.size()/2);
					if(allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
					int ret = 1;
					ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
										allmetadata_str.data(), allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string txid_str = "f6834b5c228278d51e5986a568324edb4cbf26ee8cf7fc23843d1b1cb0df005f";
					if(txid_str.size()!=tx.m_txid.size()*2) throw std::invalid_argument("Bad txid size");
					ret = sodium_hex2bin(tx.m_txid.data(), tx.m_txid.size(),
										txid_str.data(), txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					tx.m_type = t_transactiontype::add_open_vote;
					const std::string pk_str = "df3dcc390cae59adab07f0225582a78f85ba72c54f63adebdccbe7127d878305";
					if(pk_str.size()!=tx.m_vin.at(0).m_pk.size()*2) throw std::invalid_argument("Bad vin pk size");
					ret = sodium_hex2bin(tx.m_vin.at(0).m_pk.data(), tx.m_vin.at(0).m_pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string sign_str = "8fec492b8d33247ff1f306707fa60978500222b41f1183a24fb3a5200d6b136b9c0c607fd21dcbd41e1e8e44a0db60a9964b445dffc83a193a084299f031f900";
					if(sign_str.size()!=tx.m_vin.at(0).m_sign.size()*2) throw std::invalid_argument("Bad vin sign size");
					ret = sodium_hex2bin(tx.m_vin.at(0).m_sign.data(), tx.m_vin.at(0).m_sign.size(),
										sign_str.data(), sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					const std::string vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					if(vin_txid_str.size()!=tx.m_vin.at(0).m_txid.size()*2) throw std::invalid_argument("Bad vin txid size");
					ret = sodium_hex2bin(tx.m_vin.at(0).m_txid.data(), tx.m_vin.at(0).m_txid.size(),
										vin_txid_str.data(), vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					tx.m_vout.at(0).m_amount = 1;
					const std::string pkh_str = "99deaab034ed6921f3c6c1281706f0c7a1335650ee1023add6794787504ec39c";
					if(pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad pkh size");
					ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
										pkh_str.data(), pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_transactions_from_mempool.m_transactions.push_back(tx);
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_transactions_from_mempool";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["allmetadata"], "5649beb99ecdd5d0ba5dc51ce2306f044fe2a97e94e2c1f732818258d6d8da417d6d");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["txid"], "f6834b5c228278d51e5986a568324edb4cbf26ee8cf7fc23843d1b1cb0df005f");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["type"], 1);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["pk"], "df3dcc390cae59adab07f0225582a78f85ba72c54f63adebdccbe7127d878305");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["sign"], "8fec492b8d33247ff1f306707fa60978500222b41f1183a24fb3a5200d6b136b9c0c607fd21dcbd41e1e8e44a0db60a9964b445dffc83a193a084299f031f900");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["amount"], 1);
	EXPECT_EQ(result["result"]["data"]["transactions"].at(0)["vout"].at(0)["pkh"], "99deaab034ed6921f3c6c1281706f0c7a1335650ee1023add6794787504ec39c");
}

TEST_F(rpc, get_metadata_from_tx) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_metadata_from_tx = dynamic_cast<const t_mediator_command_request_get_metadata_from_tx&>(request);
					response = std::make_unique<t_mediator_command_response_get_metadata_from_tx>();
					auto & response_get_metadata_from_tx = dynamic_cast<t_mediator_command_response_get_metadata_from_tx&>(*response);
					const std::string txid_str = "8572f7a74dd92ee5bb5638f57d1bbfef9514720b5d29a9d0d0d78ff6a642181d";
					t_hash_type txid;
					if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
					int ret = 1;
					ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_str.data(), txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_metadata_from_tx.m_txid, txid);
					const std::string metadata_str = "766f74696e675f32";
					std::vector<unsigned char> metadata;
					metadata.resize(metadata_str.size()/2);
					if(metadata_str.size()!=metadata.size()*2) throw std::invalid_argument("Bad metadata size");
					ret = sodium_hex2bin(metadata.data(), metadata.size(),
										metadata_str.data(), metadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_metadata_from_tx.m_metadata_from_tx = metadata;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_metadata_from_tx";
	cmd["params"]["txid"] = "8572f7a74dd92ee5bb5638f57d1bbfef9514720b5d29a9d0d0d78ff6a642181d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["metadata"], "766f74696e675f32");
}

TEST_F(rpc, get_last_block_time) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_last_block_time>();
					auto & response_get_last_block_time = dynamic_cast<t_mediator_command_response_get_last_block_time&>(*response);
					response_get_last_block_time.m_block_time = 1666952919;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_last_block_time";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["last_block_time"], 1666952919);
}

TEST_F(rpc, get_source_txid_using_pk_voter) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					switch (request.m_type) {
						case t_mediator_cmd_type::e_is_authorized:
						{
							const auto request_is_authorized = dynamic_cast<const t_mediator_command_request_is_authorized&>(request);
							response = std::make_unique<t_mediator_command_response_is_authorized>();
							auto & response_is_authorized = dynamic_cast<t_mediator_command_response_is_authorized&>(*response);
							t_public_key_type pk;
							const std::string pk_str = "cc1217549d81c7f5a76cc87fb9adfeb01acfa90220720d6a82a9d6aa41e8db07";
							if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
							int ret = 1;
							ret = sodium_hex2bin(pk.data(), pk.size(),
												pk_str.data(), pk_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							EXPECT_EQ(request_is_authorized.m_pk, pk);
							response_is_authorized.m_auth_data.resize(1);
							t_hash_type txid;
							const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
							if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
							ret = sodium_hex2bin(txid.data(), txid.size(),
												txid_str.data(), txid_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							response_is_authorized.m_auth_data.at(0).m_txid = txid;
							response_is_authorized.m_auth_data.at(0).m_type_of_transaction = t_transactiontype::authorize_voter;
							t_public_key_type voting_group;
							const std::string voting_group_str = "8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
							if(voting_group_str.size()!=voting_group.size()*2) throw std::invalid_argument("Bad voting group size");
							ret = sodium_hex2bin(voting_group.data(), voting_group.size(),
												voting_group_str.data(), voting_group_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							response_is_authorized.m_auth_data.at(0).m_voting_group = voting_group;
							response_is_authorized.m_is_adminsys = false;
							break;
						}
						case t_mediator_cmd_type::e_get_voter_auth_txid_for_voting:
						{
							const auto request_get_auth_voter_txid = dynamic_cast<const t_mediator_command_request_get_voter_auth_txid_for_voting&>(request);
							response = std::make_unique<t_mediator_command_response_get_voter_auth_txid_for_voting>();
							auto & response_get_voter_auth_txid = dynamic_cast<t_mediator_command_response_get_voter_auth_txid_for_voting&>(*response);
							const std::string pk_str = "cc1217549d81c7f5a76cc87fb9adfeb01acfa90220720d6a82a9d6aa41e8db07";
							t_hash_type pk;
							if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
							int ret = 1;
							ret = sodium_hex2bin(pk.data(), pk.size(),
												pk_str.data(), pk_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							EXPECT_EQ(request_get_auth_voter_txid.m_voter_pk, pk);
							const std::string voting_id_str = "c05effef46c30d73e54f15731faac9340a9e42ff929dbb5abee8efabb2dba255";
							t_hash_type voting_id;
							if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
							ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
												voting_id_str.data(), voting_id_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							EXPECT_EQ(request_get_auth_voter_txid.m_voting_id, voting_id);
							const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
							t_hash_type txid;
							if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
							ret = sodium_hex2bin(txid.data(), txid.size(),
												txid_str.data(), txid_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							response_get_voter_auth_txid.m_txid = txid;
							break;
						}
						default:
						break;
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_source_txid";
	cmd["params"]["pk"] = "cc1217549d81c7f5a76cc87fb9adfeb01acfa90220720d6a82a9d6aa41e8db07";
	cmd["params"]["voting_id"] = "c05effef46c30d73e54f15731faac9340a9e42ff929dbb5abee8efabb2dba255";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
}

TEST_F(rpc, get_source_txid_using_pk_of_other_actor_than_voter) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					switch (request.m_type) {
						case t_mediator_cmd_type::e_is_authorized:
						{
							const auto request_is_authorized = dynamic_cast<const t_mediator_command_request_is_authorized&>(request);
							response = std::make_unique<t_mediator_command_response_is_authorized>();
							auto & response_is_authorized = dynamic_cast<t_mediator_command_response_is_authorized&>(*response);
							t_public_key_type pk;
							const std::string pk_str = "cc1217549d81c7f5a76cc87fb9adfeb01acfa90220720d6a82a9d6aa41e8db07";
							if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
							int ret = 1;
							ret = sodium_hex2bin(pk.data(), pk.size(),
												pk_str.data(), pk_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							EXPECT_EQ(request_is_authorized.m_pk, pk);
							response_is_authorized.m_auth_data.resize(1);
							t_hash_type txid;
							const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
							if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
							ret = sodium_hex2bin(txid.data(), txid.size(),
												txid_str.data(), txid_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							response_is_authorized.m_auth_data.at(0).m_txid = txid;
							response_is_authorized.m_auth_data.at(0).m_type_of_transaction = t_transactiontype::authorize_issuer;
							t_public_key_type voting_group;
							const std::string voting_group_str = "8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
							if(voting_group_str.size()!=voting_group.size()*2) throw std::invalid_argument("Bad voting group size");
							ret = sodium_hex2bin(voting_group.data(), voting_group.size(),
												voting_group_str.data(), voting_group_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							response_is_authorized.m_auth_data.at(0).m_voting_group = voting_group;
							response_is_authorized.m_is_adminsys = false;
							break;
						}
						case t_mediator_cmd_type::e_get_source_txid_for_pkh:
						{
							const auto request_get_source_txid = dynamic_cast<const t_mediator_command_request_get_source_txid_for_pkh&>(request);
							response = std::make_unique<t_mediator_command_response_get_source_txid_for_pkh>();
							auto & response_get_source_txid = dynamic_cast<t_mediator_command_response_get_source_txid_for_pkh&>(*response);
							const std::string pk_str = "cc1217549d81c7f5a76cc87fb9adfeb01acfa90220720d6a82a9d6aa41e8db07";
							t_hash_type pk;
							if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
							int ret = 1;
							ret = sodium_hex2bin(pk.data(), pk.size(),
												pk_str.data(), pk_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							EXPECT_EQ(request_get_source_txid.m_pkh, generate_hash(pk));
							const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
							t_hash_type txid;
							if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
							ret = sodium_hex2bin(txid.data(), txid.size(),
												txid_str.data(), txid_str.size(),
												nullptr, nullptr, nullptr);
							if (ret!=0) throw std::runtime_error("hex2bin error");
							response_get_source_txid.m_txid = txid;
							break;
						}
						default:
						break;
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_source_txid";
	cmd["params"]["pk"] = "cc1217549d81c7f5a76cc87fb9adfeb01acfa90220720d6a82a9d6aa41e8db07";
	cmd["params"]["voting_id"] = "c05effef46c30d73e54f15731faac9340a9e42ff929dbb5abee8efabb2dba255";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
}

TEST_F(rpc, get_all_vote_transactions) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto & request_get_all_vote_transactions = dynamic_cast<const t_mediator_command_request_get_all_vote_transactions&>(request);
					response = std::make_unique<t_mediator_command_response_get_all_vote_transactions>();
					auto & response_get_all_vote_transactions = dynamic_cast<t_mediator_command_response_get_all_vote_transactions&>(*response);
					t_hash_type voting_id;
					const std::string voting_id_str = "ff00996927319f77e9bbef3b438adb094ef6343f921ea4da8efec0f3d41dbf33";
					if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
					int ret = 1;
					ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
										voting_id_str.data(), voting_id_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_all_vote_transactions.m_voting_id, voting_id);
					const std::string tx_allmetadata_str = "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
					std::vector<unsigned char> allmetadata;
					allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_all_vote_transactions.m_vote_transactions.resize(1);
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_allmetadata = allmetadata;
					const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					t_hash_type txid;
					if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_txid = txid;
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_type = t_transactiontype::add_secret_vote;
					const std::string tx_vin_pk_str = "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef";
					t_public_key_type pk;
					if(tx_vin_pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_vin.resize(1);
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_vin.at(0).m_pk = pk;
					const std::string tx_vin_sign_str = "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305";
					t_signature_type sign;
					if(tx_vin_sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(sign.data(), sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_vin.at(0).m_sign = sign;
					const std::string tx_vin_txid_str = "10dce062b0358aa83616ce8f7b85510bd656a9d30c0a4b25f8979e24c6196c16";
					t_hash_type vin_txid;
					if(tx_vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_vin.at(0).m_txid = vin_txid;
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_vout.resize(1);
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_vout.at(0).m_amount = 1;
					const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
					t_hash_type pkh;
					if(tx_vout_pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size from tx");
					ret = sodium_hex2bin(pkh.data(), pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_all_vote_transactions.m_vote_transactions.at(0).m_vout.at(0).m_pkh = pkh;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_all_vote_transactions";
	cmd["params"]["voting_id"] = "ff00996927319f77e9bbef3b438adb094ef6343f921ea4da8efec0f3d41dbf33";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"].at(0)["allmetadata"], "434f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea");
	EXPECT_EQ(result["result"]["data"].at(0)["txid"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"].at(0)["type"], 0);
	EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["pk"], "6e07388956fded045fa877ea0e2d1ad5bc465ae9052219f8114a5ee31e025eef");
	EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["sign"], "44aa7c22e4d8a9395c2e8698890d915ca2045085a62ebe128159ae55bde9b69f659fc4f86e63c7a4c395a3c7c0da6575f627b3b8dbe213d29c8f6ee23d59b305");
	EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["vin_txid"], "10dce062b0358aa83616ce8f7b85510bd656a9d30c0a4b25f8979e24c6196c16");
	EXPECT_EQ(result["result"]["data"].at(0)["vout"].at(0)["amount"], 1);
	EXPECT_EQ(result["result"]["data"].at(0)["vout"].at(0)["pkh"], "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3");
}

TEST_F(rpc, get_voter_groups) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					const auto & request_get_voter_groups = dynamic_cast<const t_mediator_command_request_get_voter_groups&>(request);
					response = std::make_unique<t_mediator_command_response_get_voter_groups>();
					auto & response_get_voter_groups = dynamic_cast<t_mediator_command_response_get_voter_groups&>(*response);
					t_public_key_type pk;
					const std::string pk_str = "10aa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					int ret = 1;
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_voter_groups.m_voter_pk, pk);
					t_hash_type voter_group;
					const std::string voter_group_str = "14cd072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe193c91";
					if(voter_group_str.size()!=voter_group.size()*2) throw std::invalid_argument("Bad voter_group size");
					ret = sodium_hex2bin(voter_group.data(), voter_group.size(),
										voter_group_str.data(), voter_group_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_voter_groups.m_voter_groups.push_back(voter_group);
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_voter_groups";
	cmd["params"]["voter_pk"] = "10aa072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe1940bc";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["voter_groups"].at(0), "14cd072722b5276e18673512c83ea34be2c16822a9793ca98d0d29befe193c91");
}

TEST_F(rpc, get_number_of_all_voters) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_all_voters>();
					auto & response_get_number_of_all_voters = dynamic_cast<t_mediator_command_response_get_number_of_all_voters&>(*response);
					response_get_number_of_all_voters.m_number_of_all_voters = 10000;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_all_voters";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["number_of_all_voters"], 10000);
}

TEST_F(rpc, get_number_of_miners) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_miners>();
					auto & response_get_number_of_miners = dynamic_cast<t_mediator_command_response_get_number_of_miners&>(*response);
					response_get_number_of_miners.m_number_of_miners = 2;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_miners";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["number_of_miners"], 2);
}

TEST_F(rpc, get_number_of_all_active_votings) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_all_active_votings>();
					auto & response_get_number_of_all_active_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_active_votings&>(*response);
					response_get_number_of_all_active_votings.m_number_of_all_active_votings = 1;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_all_active_votings";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], 1);
}

TEST_F(rpc, get_number_of_all_votings) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_all_votings>();
					auto & response_get_number_of_all_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_votings&>(*response);
					response_get_number_of_all_votings.m_number_of_all_votings = 3;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_all_votings";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], 3);
}

TEST_F(rpc, get_number_of_all_inactive_votings) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_all_inactive_votings>();
					auto & response_get_number_of_all_inactive_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_inactive_votings&>(*response);
					response_get_number_of_all_inactive_votings.m_number_of_all_inactive_votings = 2;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_all_inactive_votings";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], 2);
}

TEST_F(rpc, get_number_of_all_finished_votings) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_all_finished_votings>();
					auto & response_get_number_of_all_finished_votings = dynamic_cast<t_mediator_command_response_get_number_of_all_finished_votings&>(*response);
					response_get_number_of_all_finished_votings.m_number_of_all_finished_votings = 4;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_all_finished_votings";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], 4);
}

TEST_F(rpc, get_number_of_all_added_votes) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_all_added_votes>();
					auto & response_get_number_of_all_added_votes = dynamic_cast<t_mediator_command_response_get_number_of_all_added_votes&>(*response);
					response_get_number_of_all_added_votes.m_number_of_all_added_votes = 100000;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_all_added_votes";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], 100000);
}

TEST_F(rpc, get_number_of_all_transactions) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_number_of_all_transactions>();
					auto & response_get_number_of_all_transactions = dynamic_cast<t_mediator_command_response_get_number_of_all_transactions&>(*response);
					response_get_number_of_all_transactions.m_number_of_all_transactions = 1453453;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_number_of_all_transactions";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"], 1453453);
}

TEST_F(rpc, get_last_5_blocks) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_last_5_blocks>();
					auto & response_get_last_5_blocks = dynamic_cast<t_mediator_command_response_get_last_5_blocks&>(*response);
					response_get_last_5_blocks.m_last_5_blocks.resize(5);
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "570530f61eaa55c9b63b05b6b410c23c9ef52af1f6108e1e8021986eab1d79af";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_blocks.m_last_5_blocks.at(0).m_header.m_actual_hash = actual_hash;
						response_get_last_5_blocks.m_last_5_blocks.at(0).m_header.m_block_time = 1679079787;
						response_get_last_5_blocks.m_last_5_blocks.at(0).m_number_of_transactions = 1386;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "4395269910fbc8a1a0e38ffa6619e6647ac6e3c7112f3d13e5d134254b8983a9";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_blocks.m_last_5_blocks.at(1).m_header.m_actual_hash = actual_hash;
						response_get_last_5_blocks.m_last_5_blocks.at(1).m_header.m_block_time = 1679079784;
						response_get_last_5_blocks.m_last_5_blocks.at(1).m_number_of_transactions = 4538;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "9d445df73b23251819560e6e07aebbf0e7452e80b4f7c5694c96ca10e42d1a2d";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_blocks.m_last_5_blocks.at(2).m_header.m_actual_hash = actual_hash;
						response_get_last_5_blocks.m_last_5_blocks.at(2).m_header.m_block_time = 1679079781;
						response_get_last_5_blocks.m_last_5_blocks.at(2).m_number_of_transactions = 4538;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "501dd0dc3cbf8dd80d0a676b3dd55b3ad309190b8443ec28abac96390604dfd3";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_blocks.m_last_5_blocks.at(3).m_header.m_actual_hash = actual_hash;
						response_get_last_5_blocks.m_last_5_blocks.at(3).m_header.m_block_time = 1679079778;
						response_get_last_5_blocks.m_last_5_blocks.at(3).m_number_of_transactions = 4538;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "ef04b43a5c7f9aa20c320736d7be250eb7d135c049a7561276f333d2349e9113";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_blocks.m_last_5_blocks.at(4).m_header.m_actual_hash = actual_hash;
						response_get_last_5_blocks.m_last_5_blocks.at(4).m_header.m_block_time = 1679079775;
						response_get_last_5_blocks.m_last_5_blocks.at(4).m_number_of_transactions = 638;
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_last_5_blocks";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(0)["block_id"], "570530f61eaa55c9b63b05b6b410c23c9ef52af1f6108e1e8021986eab1d79af");
		EXPECT_EQ(result["result"]["data"].at(0)["block_time"], 1679079787);
		EXPECT_EQ(result["result"]["data"].at(0)["number_of_transactions"], 1386);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(1)["block_id"], "4395269910fbc8a1a0e38ffa6619e6647ac6e3c7112f3d13e5d134254b8983a9");
		EXPECT_EQ(result["result"]["data"].at(1)["block_time"], 1679079784);
		EXPECT_EQ(result["result"]["data"].at(1)["number_of_transactions"], 4538);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(2)["block_id"], "9d445df73b23251819560e6e07aebbf0e7452e80b4f7c5694c96ca10e42d1a2d");
		EXPECT_EQ(result["result"]["data"].at(2)["block_time"], 1679079781);
		EXPECT_EQ(result["result"]["data"].at(2)["number_of_transactions"], 4538);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(3)["block_id"], "501dd0dc3cbf8dd80d0a676b3dd55b3ad309190b8443ec28abac96390604dfd3");
		EXPECT_EQ(result["result"]["data"].at(3)["block_time"], 1679079778);
		EXPECT_EQ(result["result"]["data"].at(3)["number_of_transactions"], 4538);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(4)["block_id"], "ef04b43a5c7f9aa20c320736d7be250eb7d135c049a7561276f333d2349e9113");
		EXPECT_EQ(result["result"]["data"].at(4)["block_time"], 1679079775);
		EXPECT_EQ(result["result"]["data"].at(4)["number_of_transactions"], 638);
	}
}

TEST_F(rpc, get_last_5_transactions) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_last_5_transactions>();
					auto & response_get_last_5_transactions = dynamic_cast<t_mediator_command_response_get_last_5_transactions&>(*response);
					response_get_last_5_transactions.m_last_5_transactions.resize(5);
					{
						const std::string allmetadata_str = "5649050f993e64023a55633540fbc47834842b7ff0c84b1b5c8919d7683205944c9c";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_allmetadata = allmetadata;
						const std::string txid_str = "00335181907a5bbef57597357664dc1f444241d7175ba1a51741bf5e56dcc6eb";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_txid = txid;
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_type = t_transactiontype::add_secret_vote;
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_vin.resize(1);
						const std::string pk_str = "abcdc51c27df814eaf68b908204d067570a3bdc60e7f96c1cafe5110473d3587";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d69023dccf9d6e0f88ee13ac2e6dc2aac2e27c7b58ac39e4f6449e527105d7216d3643de18072b7660b5ac858842d43d2ef4d5d2b83d92e04ed0c0d4966bbc0c";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "05c2a2f1aae193036e366a39117af76f62570f3a4749cc3459a957e758286e8b";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_vin.at(0).m_txid = vin_txid;
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_vout.resize(1);
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "d8d5940c5d8db60825871c6a322cbde6570a540b3cf46d4ee4feaba63379ad8b";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(0).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "564971d556102de6508d6015964460df2fb11199853d711d608fc077874e806a452b";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_allmetadata = allmetadata;
						const std::string txid_str = "0043daa78f88635f011f590230225c493a932ad83d45ef9ee2de28909a915370";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_txid = txid;
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_type = t_transactiontype::add_secret_vote;
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_vin.resize(1);
						const std::string pk_str = "ae327da95f56c2277bb2dee622d13f53701062f9f70cc545d088966a60ac5d95";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d3d144e1e593d479b0e58b46115f4d799e1a9b44f2e0d11a3c9d0203bf9e1ed373892f680636501243b5c26265979052b70636128b91655da28aba9a81ff2105";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "7d11e113ec9888b304b22071f1a69fb3ae4bc6ccd0bdabada1fbf374094c467a";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_vin.at(0).m_txid = vin_txid;
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_vout.resize(1);
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "921102ba4a0da7e9c57e91d7fada97f255459bdfbf709d4ef22be5cae919a982";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(1).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649b17b354cea209617796948c2583781177b03bd949a542ede1613d9c1fd479980";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_allmetadata = allmetadata;
						const std::string txid_str = "00b26524da05a626067c3f54aa29d0cec44085a0f736ab46575b8af0912dac02";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_txid = txid;
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_type = t_transactiontype::add_secret_vote;
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_vin.resize(1);
						const std::string pk_str = "08a4b465c395859af0d2326310f09c22fdb68910655359a4bbf1be6866c411df";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "6bc7ed36ef9578ed175f059d9468469ce2567aee7f523b1d3c3ca1e860f7b8227ea28aeedb28ed8e4fc7e172aa7d7588930a2f90b4310ecd1082a649ad4ef407";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "c89ba3fcb2d233aca4bc58cf17f2010c4d9130a173f2c3f1d700442466cd9635";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_vin.at(0).m_txid = vin_txid;
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_vout.resize(1);
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "0cddcd990b20a93220678ee0e226270717de11cc9293eba43d78b61bcbb66d59";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(2).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "564940c4d0618a3cdf685e26d7c2f606901d588ec53c783b01c469670f8e38420502";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_allmetadata = allmetadata;
						const std::string txid_str = "00d43ddab4f67481e375b19f89e1e2cfbc0d597a46d58525343524e7536e6872";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_txid = txid;
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_type = t_transactiontype::add_secret_vote;
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_vin.resize(1);
						const std::string pk_str = "2a54a964ad75cc3665b43f77350a90bc80e28107ba42727aab7457731aa4e872";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "11ea37a644e7df70955e9d21994a4c9c3abe290b17f3893c8f07d21587ca2e4815dd95add104ad38ee8cb60a557f0cb6275cd7c3d7ca4ba3054de8588c387101";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "73958781954b6f93cdc62dcbe685d748e78ae4e2bfadebfa586fea1f468b5798";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_vin.at(0).m_txid = vin_txid;
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_vout.resize(1);
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "77bae17ef129b00c3b7f138343bb267b1edb57c0d25d6a9251fe2fb0621456a7";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(3).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649005e3ae78db4cf7a52e8e54c067e20c65fe4ffa3dba8a4e20ae6da0c164ae1e3";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_allmetadata = allmetadata;
						const std::string txid_str = "00d48b4e124cbfcb9d93fad5f3bb12c5641e2a9633d6ca52f011e92427807dae";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_txid = txid;
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_type = t_transactiontype::add_secret_vote;
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_vin.resize(1);
						const std::string pk_str = "0ac766836a937c76079f29df0685164588f8676424eff8b02d454a8c83364eff";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "a420e4eb3845c923f58414e20829482a95c8ce90454cdbcadbcf2d2018ff1b7f559f0c23216c422dfab47d9ab1cb80671b84a9c075f1757e57e47ea6f7f8b107";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "f1a01888f9fa72c140a9265202d7db266f9ce3198a35df06b91a45e1aa75af5b";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_vin.at(0).m_txid = vin_txid;
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_vout.resize(1);
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "457927ac5e2493baa0076d74452cc22073f07ffc7a9962eaa540b0b0b74d3f97";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_transactions.m_last_5_transactions.at(4).m_vout.at(0).m_pkh = pkh;
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_last_5_transactions";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(0)["allmetadata"], "5649050f993e64023a55633540fbc47834842b7ff0c84b1b5c8919d7683205944c9c");
		EXPECT_EQ(result["result"]["data"].at(0)["txid"], "00335181907a5bbef57597357664dc1f444241d7175ba1a51741bf5e56dcc6eb");
		EXPECT_EQ(result["result"]["data"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["pk"], "abcdc51c27df814eaf68b908204d067570a3bdc60e7f96c1cafe5110473d3587");
		EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["sign"], "d69023dccf9d6e0f88ee13ac2e6dc2aac2e27c7b58ac39e4f6449e527105d7216d3643de18072b7660b5ac858842d43d2ef4d5d2b83d92e04ed0c0d4966bbc0c");
		EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["vin_txid"], "05c2a2f1aae193036e366a39117af76f62570f3a4749cc3459a957e758286e8b");
		EXPECT_EQ(result["result"]["data"].at(0)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"].at(0)["vout"].at(0)["pkh"], "d8d5940c5d8db60825871c6a322cbde6570a540b3cf46d4ee4feaba63379ad8b");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(1)["allmetadata"], "564971d556102de6508d6015964460df2fb11199853d711d608fc077874e806a452b");
		EXPECT_EQ(result["result"]["data"].at(1)["txid"], "0043daa78f88635f011f590230225c493a932ad83d45ef9ee2de28909a915370");
		EXPECT_EQ(result["result"]["data"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(1)["vin"].at(0)["pk"], "ae327da95f56c2277bb2dee622d13f53701062f9f70cc545d088966a60ac5d95");
		EXPECT_EQ(result["result"]["data"].at(1)["vin"].at(0)["sign"], "d3d144e1e593d479b0e58b46115f4d799e1a9b44f2e0d11a3c9d0203bf9e1ed373892f680636501243b5c26265979052b70636128b91655da28aba9a81ff2105");
		EXPECT_EQ(result["result"]["data"].at(1)["vin"].at(0)["vin_txid"], "7d11e113ec9888b304b22071f1a69fb3ae4bc6ccd0bdabada1fbf374094c467a");
		EXPECT_EQ(result["result"]["data"].at(1)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"].at(1)["vout"].at(0)["pkh"], "921102ba4a0da7e9c57e91d7fada97f255459bdfbf709d4ef22be5cae919a982");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(2)["allmetadata"], "5649b17b354cea209617796948c2583781177b03bd949a542ede1613d9c1fd479980");
		EXPECT_EQ(result["result"]["data"].at(2)["txid"], "00b26524da05a626067c3f54aa29d0cec44085a0f736ab46575b8af0912dac02");
		EXPECT_EQ(result["result"]["data"].at(2)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(2)["vin"].at(0)["pk"], "08a4b465c395859af0d2326310f09c22fdb68910655359a4bbf1be6866c411df");
		EXPECT_EQ(result["result"]["data"].at(2)["vin"].at(0)["sign"], "6bc7ed36ef9578ed175f059d9468469ce2567aee7f523b1d3c3ca1e860f7b8227ea28aeedb28ed8e4fc7e172aa7d7588930a2f90b4310ecd1082a649ad4ef407");
		EXPECT_EQ(result["result"]["data"].at(2)["vin"].at(0)["vin_txid"], "c89ba3fcb2d233aca4bc58cf17f2010c4d9130a173f2c3f1d700442466cd9635");
		EXPECT_EQ(result["result"]["data"].at(2)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"].at(2)["vout"].at(0)["pkh"], "0cddcd990b20a93220678ee0e226270717de11cc9293eba43d78b61bcbb66d59");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(3)["allmetadata"], "564940c4d0618a3cdf685e26d7c2f606901d588ec53c783b01c469670f8e38420502");
		EXPECT_EQ(result["result"]["data"].at(3)["txid"], "00d43ddab4f67481e375b19f89e1e2cfbc0d597a46d58525343524e7536e6872");
		EXPECT_EQ(result["result"]["data"].at(3)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(3)["vin"].at(0)["pk"], "2a54a964ad75cc3665b43f77350a90bc80e28107ba42727aab7457731aa4e872");
		EXPECT_EQ(result["result"]["data"].at(3)["vin"].at(0)["sign"], "11ea37a644e7df70955e9d21994a4c9c3abe290b17f3893c8f07d21587ca2e4815dd95add104ad38ee8cb60a557f0cb6275cd7c3d7ca4ba3054de8588c387101");
		EXPECT_EQ(result["result"]["data"].at(3)["vin"].at(0)["vin_txid"], "73958781954b6f93cdc62dcbe685d748e78ae4e2bfadebfa586fea1f468b5798");
		EXPECT_EQ(result["result"]["data"].at(3)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"].at(3)["vout"].at(0)["pkh"], "77bae17ef129b00c3b7f138343bb267b1edb57c0d25d6a9251fe2fb0621456a7");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(4)["allmetadata"], "5649005e3ae78db4cf7a52e8e54c067e20c65fe4ffa3dba8a4e20ae6da0c164ae1e3");
		EXPECT_EQ(result["result"]["data"].at(4)["txid"], "00d48b4e124cbfcb9d93fad5f3bb12c5641e2a9633d6ca52f011e92427807dae");
		EXPECT_EQ(result["result"]["data"].at(4)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(4)["vin"].at(0)["pk"], "0ac766836a937c76079f29df0685164588f8676424eff8b02d454a8c83364eff");
		EXPECT_EQ(result["result"]["data"].at(4)["vin"].at(0)["sign"], "a420e4eb3845c923f58414e20829482a95c8ce90454cdbcadbcf2d2018ff1b7f559f0c23216c422dfab47d9ab1cb80671b84a9c075f1757e57e47ea6f7f8b107");
		EXPECT_EQ(result["result"]["data"].at(4)["vin"].at(0)["vin_txid"], "f1a01888f9fa72c140a9265202d7db266f9ce3198a35df06b91a45e1aa75af5b");
		EXPECT_EQ(result["result"]["data"].at(4)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"].at(4)["vout"].at(0)["pkh"], "457927ac5e2493baa0076d74452cc22073f07ffc7a9962eaa540b0b0b74d3f97");
	}
}

TEST_F(rpc, get_last_5_votings) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](){
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_last_5_votings>();
					auto & response_get_last_5_votings = dynamic_cast<t_mediator_command_response_get_last_5_votings&>(*response);
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679183050;
						const uint32_t voting_end_time = 1679189050;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting D";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_votings.m_last_5_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_last_5_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 0.0));
						response_get_last_5_votings.m_is_waiting.push_back(voting_id);
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079730;
						const uint32_t voting_end_time = 1679183030;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting C";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_votings.m_last_5_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_last_5_votings.m_is_finished.push_back(std::make_pair(voting_id, false));
						response_get_last_5_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 57.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079630;
						const uint32_t voting_end_time = 1679093130;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_votings.m_last_5_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_last_5_votings.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_last_5_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079530;
						const uint32_t voting_end_time = 1679093030;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "fc6001a560a35b411991055f0f5d2e8484fb42755a4e15059b0ba9b34fd2be7a";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_votings.m_last_5_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_last_5_votings.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_last_5_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679078630;
						const uint32_t voting_end_time = 1679083130;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_last_5_votings.m_last_5_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_last_5_votings.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_last_5_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_last_5_votings";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(0)["end_time"], 1679189050);
		EXPECT_EQ(result["result"]["data"].at(0)["name"], "Voting D");
		EXPECT_EQ(result["result"]["data"].at(0)["start_time"], 1679183050);
		EXPECT_EQ(result["result"]["data"].at(0)["status"], "waiting");
		EXPECT_EQ(result["result"]["data"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(0)["voter_turnout"], 0.0);
		EXPECT_EQ(result["result"]["data"].at(0)["voting_id"], "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(1)["end_time"], 1679183030);
		EXPECT_EQ(result["result"]["data"].at(1)["name"], "Voting C");
		EXPECT_EQ(result["result"]["data"].at(1)["start_time"], 1679079730);
		EXPECT_EQ(result["result"]["data"].at(1)["status"], "active");
		EXPECT_EQ(result["result"]["data"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(1)["voter_turnout"], 57.0);
		EXPECT_EQ(result["result"]["data"].at(1)["voting_id"], "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(2)["end_time"], 1679093130);
		EXPECT_EQ(result["result"]["data"].at(2)["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"].at(2)["start_time"], 1679079630);
		EXPECT_EQ(result["result"]["data"].at(2)["status"], "finished");
		EXPECT_EQ(result["result"]["data"].at(2)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(2)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"].at(2)["voting_id"], "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(3)["end_time"], 1679093030);
		EXPECT_EQ(result["result"]["data"].at(3)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"].at(3)["start_time"], 1679079530);
		EXPECT_EQ(result["result"]["data"].at(3)["status"], "finished");
		EXPECT_EQ(result["result"]["data"].at(3)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(3)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"].at(3)["voting_id"], "fc6001a560a35b411991055f0f5d2e8484fb42755a4e15059b0ba9b34fd2be7a");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(4)["end_time"], 1679083130);
		EXPECT_EQ(result["result"]["data"].at(4)["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"].at(4)["start_time"], 1679078630);
		EXPECT_EQ(result["result"]["data"].at(4)["status"], "finished");
		EXPECT_EQ(result["result"]["data"].at(4)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(4)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"].at(4)["voting_id"], "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e");
	}
}

TEST_F(rpc, get_block_by_id_without_txs_and_signs) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
	            	const auto request_get_block_by_id = dynamic_cast<const t_mediator_command_request_get_block_by_id_without_txs_and_signs&>(request);
					response = std::make_unique<t_mediator_command_response_get_block_by_id_without_txs_and_signs>();
					auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_id_without_txs_and_signs&>(*response);
					t_hash_type actual_hash;
					const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
					if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
					int ret = 1;
					ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
										actual_hash_str.data(), actual_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_actual_hash = actual_hash;
					EXPECT_EQ(request_get_block_by_id.m_block_hash, actual_hash);
					t_hash_type all_tx_hash;
					const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
					ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
										all_tx_hash_str.data(), all_tx_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_tx_hash = all_tx_hash;
					response_get_block.m_block.m_header.m_block_time = 1679079676;
					t_hash_type parent_hash;
					const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
					if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
					ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
										parent_hash_str.data(), parent_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_parent_hash = parent_hash;
					response_get_block.m_block.m_header.m_version = 0;
					response_get_block.m_block.m_transaction.resize(1);
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_block_by_id_without_txs_and_signs";
	cmd["params"]["block_id"] = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["actual_hash"], "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe");
	EXPECT_EQ(result["result"]["data"]["all_tx_hash"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["block_time"], 1679079676);
	EXPECT_EQ(result["result"]["data"]["parent_hash"], "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469");
	EXPECT_EQ(result["result"]["data"]["version"], 0);
	EXPECT_EQ(result["result"]["data"]["number_of_transactions"].size(), 1);
}

TEST_F(rpc, get_block_by_height_without_txs_and_signs) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
	            	const auto request_get_block_by_height = dynamic_cast<const t_mediator_command_request_get_block_by_height_without_txs_and_signs&>(request);
					response = std::make_unique<t_mediator_command_response_get_block_by_height_without_txs_and_signs>();
					auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_height_without_txs_and_signs&>(*response);
					EXPECT_EQ(request_get_block_by_height.m_height, 2);
					t_hash_type actual_hash;
					const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
					if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
					int ret = 1;
					ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
										actual_hash_str.data(), actual_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_actual_hash = actual_hash;
					t_hash_type all_tx_hash;
					const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
					ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
										all_tx_hash_str.data(), all_tx_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_tx_hash = all_tx_hash;
					response_get_block.m_block.m_header.m_block_time = 1679079676;
					t_hash_type parent_hash;
					const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
					if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
					ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
										parent_hash_str.data(), parent_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_parent_hash = parent_hash;
					response_get_block.m_block.m_header.m_version = 0;
					response_get_block.m_block.m_transaction.resize(1);
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_block_by_height_without_txs_and_signs";
	cmd["params"]["height"] = 2;
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["actual_hash"], "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe");
	EXPECT_EQ(result["result"]["data"]["all_tx_hash"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["block_time"], 1679079676);
	EXPECT_EQ(result["result"]["data"]["parent_hash"], "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469");
	EXPECT_EQ(result["result"]["data"]["version"], 0);
	EXPECT_EQ(result["result"]["data"]["number_of_transactions"].size(), 1);
}

TEST_F(rpc, get_block_by_txid_without_txs_and_signs) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_block_by_txid = dynamic_cast<const t_mediator_command_request_get_block_by_txid_without_txs_and_signs&>(request);
					response = std::make_unique<t_mediator_command_response_get_block_by_txid_without_txs_and_signs>();
					auto & response_get_block = dynamic_cast<t_mediator_command_response_get_block_by_txid_without_txs_and_signs&>(*response);
					t_hash_type txid;
					const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
					int ret = 1;
					ret = sodium_hex2bin(txid.data(), txid.size(),
										txid_str.data(), txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_block_by_txid.m_txid, txid);
					t_hash_type actual_hash;
					const std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
					if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
					ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
										actual_hash_str.data(), actual_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_actual_hash = actual_hash;
					t_hash_type all_tx_hash;
					const std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
					if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
					ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
										all_tx_hash_str.data(), all_tx_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_all_tx_hash = all_tx_hash;
					response_get_block.m_block.m_header.m_block_time = 1679079676;
					t_hash_type parent_hash;
					const std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
					if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
					ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
										parent_hash_str.data(), parent_hash_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_block.m_block.m_header.m_parent_hash = parent_hash;
					response_get_block.m_block.m_header.m_version = 0;
					response_get_block.m_block.m_transaction.resize(1);
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_block_by_txid_without_txs_and_signs";
	cmd["params"]["txid"] = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["actual_hash"], "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe");
	EXPECT_EQ(result["result"]["data"]["all_tx_hash"], "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d");
	EXPECT_EQ(result["result"]["data"]["block_time"], 1679079676);
	EXPECT_EQ(result["result"]["data"]["parent_hash"], "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469");
	EXPECT_EQ(result["result"]["data"]["version"], 0);
	EXPECT_EQ(result["result"]["data"]["number_of_transactions"].size(), 1);
}

TEST_F(rpc, get_sorted_blocks) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_blocks = dynamic_cast<const t_mediator_command_request_get_sorted_blocks_without_txs_and_signs&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_sorted_blocks_without_txs_and_signs>();
					auto & response_get_blocks = dynamic_cast<t_mediator_command_response_get_sorted_blocks_without_txs_and_signs&>(*response);
					EXPECT_EQ(request_get_blocks.m_amount_of_blocks, 2);
					response_get_blocks.m_blocks.resize(2);
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "570530f61eaa55c9b63b05b6b410c23c9ef52af1f6108e1e8021986eab1d79af";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(0).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(0).m_header.m_block_time = 1679079787;
						response_get_blocks.m_blocks.at(0).m_number_of_transactions = 1386;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "4395269910fbc8a1a0e38ffa6619e6647ac6e3c7112f3d13e5d134254b8983a9";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(1).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(1).m_header.m_block_time = 1679079784;
						response_get_blocks.m_blocks.at(1).m_number_of_transactions = 4538;
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_sorted_blocks";
	cmd["params"]["amount"] = 2;
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(0)["block_id"], "570530f61eaa55c9b63b05b6b410c23c9ef52af1f6108e1e8021986eab1d79af");
		EXPECT_EQ(result["result"]["data"].at(0)["block_time"], 1679079787);
		EXPECT_EQ(result["result"]["data"].at(0)["number_of_transactions"], 1386);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(1)["block_id"], "4395269910fbc8a1a0e38ffa6619e6647ac6e3c7112f3d13e5d134254b8983a9");
		EXPECT_EQ(result["result"]["data"].at(1)["block_time"], 1679079784);
		EXPECT_EQ(result["result"]["data"].at(1)["number_of_transactions"], 4538);
	}
}

TEST_F(rpc, get_sorted_blocks_per_page) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_blocks = dynamic_cast<const t_mediator_command_request_get_sorted_blocks_per_page_without_txs_and_signs&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs>();
					auto & response_get_blocks = dynamic_cast<t_mediator_command_response_get_sorted_blocks_per_page_without_txs_and_signs&>(*response);
					EXPECT_EQ(request_get_blocks.m_offset, 2);
					response_get_blocks.m_blocks.resize(10);
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "3ecd209c7d76071f63d44fdb430bc26f93bf677af7dc380d65be68355b6e62d2";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(0).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(0).m_header.m_block_time = 1679079757;
						response_get_blocks.m_blocks.at(0).m_number_of_transactions = 638;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "56a42f4e278803d94c43cb3340bdd0f160bd3c985ec07b18711d43366f5bd173";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(1).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(1).m_header.m_block_time = 1679079754;
						response_get_blocks.m_blocks.at(1).m_number_of_transactions = 1181;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "b08e4d3896c0c987a862f43df20da528e49573caf975e38e27aabea370f6ce72";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(2).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(2).m_header.m_block_time = 1679079751;
						response_get_blocks.m_blocks.at(2).m_number_of_transactions = 1181;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "af16f5324f0c487f70f0cd125aa389bf0ac776d33c7e39b31d40bea2f66bdb16";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(3).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(3).m_header.m_block_time = 1679079748;
						response_get_blocks.m_blocks.at(3).m_number_of_transactions = 638;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "67096d99dbf0b0bde7c502bc117b9f0ca8533509f4d643e49bbb8b4d47b02c74";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(4).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(4).m_header.m_block_time = 1679079745;
						response_get_blocks.m_blocks.at(4).m_number_of_transactions = 1181;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "5cc923bfa170f2ecfdd3507da1d9d1bb50d305209f0ccceccde94f592e78d3b1";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(5).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(5).m_header.m_block_time = 1679079742;
						response_get_blocks.m_blocks.at(5).m_number_of_transactions = 1181;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "eb50fa9d83c10886d35c51c80c9e097a307a0e8a4b68dd07e6b8192df4bdc21c";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(6).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(6).m_header.m_block_time = 1679079739;
						response_get_blocks.m_blocks.at(6).m_number_of_transactions = 638;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "c07f8c3ec93a3e7d250715e7c7f9c86c59ac493d311b3f13de5b316b29f15263";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(7).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(7).m_header.m_block_time = 1679079736;
						response_get_blocks.m_blocks.at(7).m_number_of_transactions = 1181;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "c2ddddd5fc433e817413779bfe7289290d160cc6f508fdd9f4dbcd657d350e79";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(8).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(8).m_header.m_block_time = 1679079733;
						response_get_blocks.m_blocks.at(8).m_number_of_transactions = 1181;
					}
					{
						t_hash_type actual_hash;
						const std::string actual_hash_str = "114822cb3961a98d8c79e1c3b38b39239f28d12c31a7795fb3b8f7aedd9b2297";
						if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
						const auto ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
														actual_hash_str.data(), actual_hash_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_blocks.m_blocks.at(9).m_header.m_actual_hash = actual_hash;
						response_get_blocks.m_blocks.at(9).m_header.m_block_time = 1679079730;
						response_get_blocks.m_blocks.at(9).m_number_of_transactions = 638;
					}
					response_get_blocks.m_current_height = 39;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_sorted_blocks_per_page";
	cmd["params"]["offset"] = 2;
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(0)["block_id"], "3ecd209c7d76071f63d44fdb430bc26f93bf677af7dc380d65be68355b6e62d2");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(0)["block_time"], 1679079757);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(0)["number_of_transactions"], 638);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(1)["block_id"], "56a42f4e278803d94c43cb3340bdd0f160bd3c985ec07b18711d43366f5bd173");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(1)["block_time"], 1679079754);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(1)["number_of_transactions"], 1181);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(2)["block_id"], "b08e4d3896c0c987a862f43df20da528e49573caf975e38e27aabea370f6ce72");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(2)["block_time"], 1679079751);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(2)["number_of_transactions"], 1181);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(3)["block_id"], "af16f5324f0c487f70f0cd125aa389bf0ac776d33c7e39b31d40bea2f66bdb16");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(3)["block_time"], 1679079748);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(3)["number_of_transactions"], 638);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(4)["block_id"], "67096d99dbf0b0bde7c502bc117b9f0ca8533509f4d643e49bbb8b4d47b02c74");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(4)["block_time"], 1679079745);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(4)["number_of_transactions"], 1181);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(5)["block_id"], "5cc923bfa170f2ecfdd3507da1d9d1bb50d305209f0ccceccde94f592e78d3b1");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(5)["block_time"], 1679079742);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(5)["number_of_transactions"], 1181);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(6)["block_id"], "eb50fa9d83c10886d35c51c80c9e097a307a0e8a4b68dd07e6b8192df4bdc21c");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(6)["block_time"], 1679079739);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(6)["number_of_transactions"], 638);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(7)["block_id"], "c07f8c3ec93a3e7d250715e7c7f9c86c59ac493d311b3f13de5b316b29f15263");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(7)["block_time"], 1679079736);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(7)["number_of_transactions"], 1181);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(8)["block_id"], "c2ddddd5fc433e817413779bfe7289290d160cc6f508fdd9f4dbcd657d350e79");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(8)["block_time"], 1679079733);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(8)["number_of_transactions"], 1181);
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(9)["block_id"], "114822cb3961a98d8c79e1c3b38b39239f28d12c31a7795fb3b8f7aedd9b2297");
		EXPECT_EQ(result["result"]["data"]["blocks"].at(9)["block_time"], 1679079730);
		EXPECT_EQ(result["result"]["data"]["blocks"].at(9)["number_of_transactions"], 638);
	}
	EXPECT_EQ(result["result"]["data"]["total_number_blocks"], 39);
}

TEST_F(rpc, get_latest_transactions) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_latest_transactions = dynamic_cast<const t_mediator_command_request_get_latest_txs&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_latest_txs>();
					auto & response_get_latest_transactions = dynamic_cast<t_mediator_command_response_get_latest_txs&>(*response);
					EXPECT_EQ(request_get_latest_transactions.m_amount_txs, 2);
					response_get_latest_transactions.m_transactions.resize(2);
					{
						const std::string allmetadata_str = "5649050f993e64023a55633540fbc47834842b7ff0c84b1b5c8919d7683205944c9c";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(0).m_allmetadata = allmetadata;
						const std::string txid_str = "00335181907a5bbef57597357664dc1f444241d7175ba1a51741bf5e56dcc6eb";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(0).m_txid = txid;
						response_get_latest_transactions.m_transactions.at(0).m_type = t_transactiontype::add_secret_vote;
						response_get_latest_transactions.m_transactions.at(0).m_vin.resize(1);
						const std::string pk_str = "abcdc51c27df814eaf68b908204d067570a3bdc60e7f96c1cafe5110473d3587";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(0).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d69023dccf9d6e0f88ee13ac2e6dc2aac2e27c7b58ac39e4f6449e527105d7216d3643de18072b7660b5ac858842d43d2ef4d5d2b83d92e04ed0c0d4966bbc0c";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(0).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "05c2a2f1aae193036e366a39117af76f62570f3a4749cc3459a957e758286e8b";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(0).m_vin.at(0).m_txid = vin_txid;
						response_get_latest_transactions.m_transactions.at(0).m_vout.resize(1);
						response_get_latest_transactions.m_transactions.at(0).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "d8d5940c5d8db60825871c6a322cbde6570a540b3cf46d4ee4feaba63379ad8b";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(0).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "564971d556102de6508d6015964460df2fb11199853d711d608fc077874e806a452b";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(1).m_allmetadata = allmetadata;
						const std::string txid_str = "0043daa78f88635f011f590230225c493a932ad83d45ef9ee2de28909a915370";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(1).m_txid = txid;
						response_get_latest_transactions.m_transactions.at(1).m_type = t_transactiontype::add_secret_vote;
						response_get_latest_transactions.m_transactions.at(1).m_vin.resize(1);
						const std::string pk_str = "ae327da95f56c2277bb2dee622d13f53701062f9f70cc545d088966a60ac5d95";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(1).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d3d144e1e593d479b0e58b46115f4d799e1a9b44f2e0d11a3c9d0203bf9e1ed373892f680636501243b5c26265979052b70636128b91655da28aba9a81ff2105";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(1).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "7d11e113ec9888b304b22071f1a69fb3ae4bc6ccd0bdabada1fbf374094c467a";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(1).m_vin.at(0).m_txid = vin_txid;
						response_get_latest_transactions.m_transactions.at(1).m_vout.resize(1);
						response_get_latest_transactions.m_transactions.at(1).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "921102ba4a0da7e9c57e91d7fada97f255459bdfbf709d4ef22be5cae919a982";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_transactions.m_transactions.at(1).m_vout.at(0).m_pkh = pkh;
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_latest_transactions";
	cmd["params"]["amount"] = 2;
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(0)["allmetadata"], "5649050f993e64023a55633540fbc47834842b7ff0c84b1b5c8919d7683205944c9c");
		EXPECT_EQ(result["result"]["data"].at(0)["txid"], "00335181907a5bbef57597357664dc1f444241d7175ba1a51741bf5e56dcc6eb");
		EXPECT_EQ(result["result"]["data"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["pk"], "abcdc51c27df814eaf68b908204d067570a3bdc60e7f96c1cafe5110473d3587");
		EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["sign"], "d69023dccf9d6e0f88ee13ac2e6dc2aac2e27c7b58ac39e4f6449e527105d7216d3643de18072b7660b5ac858842d43d2ef4d5d2b83d92e04ed0c0d4966bbc0c");
		EXPECT_EQ(result["result"]["data"].at(0)["vin"].at(0)["vin_txid"], "05c2a2f1aae193036e366a39117af76f62570f3a4749cc3459a957e758286e8b");
		EXPECT_EQ(result["result"]["data"].at(0)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"].at(0)["vout"].at(0)["pkh"], "d8d5940c5d8db60825871c6a322cbde6570a540b3cf46d4ee4feaba63379ad8b");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(1)["allmetadata"], "564971d556102de6508d6015964460df2fb11199853d711d608fc077874e806a452b");
		EXPECT_EQ(result["result"]["data"].at(1)["txid"], "0043daa78f88635f011f590230225c493a932ad83d45ef9ee2de28909a915370");
		EXPECT_EQ(result["result"]["data"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(1)["vin"].at(0)["pk"], "ae327da95f56c2277bb2dee622d13f53701062f9f70cc545d088966a60ac5d95");
		EXPECT_EQ(result["result"]["data"].at(1)["vin"].at(0)["sign"], "d3d144e1e593d479b0e58b46115f4d799e1a9b44f2e0d11a3c9d0203bf9e1ed373892f680636501243b5c26265979052b70636128b91655da28aba9a81ff2105");
		EXPECT_EQ(result["result"]["data"].at(1)["vin"].at(0)["vin_txid"], "7d11e113ec9888b304b22071f1a69fb3ae4bc6ccd0bdabada1fbf374094c467a");
		EXPECT_EQ(result["result"]["data"].at(1)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"].at(1)["vout"].at(0)["pkh"], "921102ba4a0da7e9c57e91d7fada97f255459bdfbf709d4ef22be5cae919a982");
	}
}

TEST_F(rpc, get_transactions_per_page) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_transactions_per_page = dynamic_cast<const t_mediator_command_request_get_txs_per_page&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_txs_per_page>();
					auto & response_get_transactions_per_page = dynamic_cast<t_mediator_command_response_get_txs_per_page&>(*response);
					EXPECT_EQ(request_get_transactions_per_page.m_offset, 4);
					response_get_transactions_per_page.m_transactions.resize(10);
					{
						const std::string allmetadata_str = "564929e20c8efd64930b410b8cd9a68b6a2147d1ff388c55d4237bf952459b7e4b02";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_allmetadata = allmetadata;
						const std::string txid_str = "069e1b1976e9658c98f39864e51c6c9228d9473f2f98370d862df63d38c3b1eb";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(0).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(0).m_vin.resize(1);
						const std::string pk_str = "b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "493946c42742b9387789b6e11516ccdd118d949bbd10d0fab2786a565aaf0578ab89cd9ba15275f1a059f78562a274a66cf20fb0ea37a6fdabd48affcbc4ff03";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "433fdd2e27094dd6ad4c0ab56a8a336e44bf3eb5990d7e326892ab805da52865";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(0).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(0).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "bc1a237e7d391019891dde86bdee44f086fe843cd5b1a55686cfbef263f1a717";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_allmetadata = allmetadata;
						const std::string txid_str = "06ae8574b3bcaeb083e493afcf8e07ab644fecb8d27a4596e7f256dd644d070e";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(1).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(1).m_vin.resize(1);
						const std::string pk_str = "b4858674fe85ebd18de759374a0ee8fa678f315ca4a32cdd9181c90c2324d78f";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "b59c00aa1e3b7b7301f638efb73e61ffd2d6a10d668c87e813127c04c7737a260da4ad0d1f7b3f16c716729813f3c1216b275c7eae807c89cf309f7f2a6e6800";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "4c3f29db495fdcbbf7ca25c6f243a6aa585e88705ba79fb06810aa21a821875f";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(1).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(1).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "accc3b80d4d340efca6cbf9c8956be1bf2f621acd67b6aa81053d396c8470a2b";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_allmetadata = allmetadata;
						const std::string txid_str = "06e2714cbf649bbec481f02967b1e5a1c87b524ab06548ab4a1425d490fdcfd4";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(2).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(2).m_vin.resize(1);
						const std::string pk_str = "52abdf6ce4c0211a3b359ed199539913d8ac351c4ec74e2e2879b3fef83055f4";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "df5b7fa80a7de4417cbc110162a21611355a5948e0db907c47c5f1ec1b5e478d29e16274fff25efd9fa4ba2982ea2288d9f59892a35061e91e9e1d384f8f9300";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "8e936675b927e8c8d7700021eafc5d59e7b388e0137d5ce77188639230c1d0e9";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(2).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(2).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "6379e76880c7b12271952b39d7e83f2d587737bbb6c7b39b2740651670618a48";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56496bd3641e9bffc16cccd298dbf9b373b978be370e18692eb59651e717bef4d74f";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_allmetadata = allmetadata;
						const std::string txid_str = "06faba732c3e93ddcfb90e311e638ca017bfaedba5a6eb544e1b9c9b217a8d6b";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(3).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(3).m_vin.resize(1);
						const std::string pk_str = "a9d54c5030625e3fcd353b966c483b3b994d0e6ede260110e0030bba31214789";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d251360b3ad715afff0edbf57b2f43a81999bb0aa86b26c51d1f9a34b58024c08211de209d1a6b9372c17c0583a7a6aefafe08eb4200e4d34abb9f825fae9a05";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "56389dfbaded59c08ee2bc9302759f22aa88de100d6b8b8c2d45ad5303bf4dbb";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(3).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(3).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "25c46cc2d5e17852be68bf33954779911fed9b7cbdb48f95b67363eef47396fb";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56490a7142afa71808a96a41a6aeccb2b5c9ea02d0b3736689472bb2433fc80e315b";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_allmetadata = allmetadata;
						const std::string txid_str = "077426406737d142630990992df79bd856a7709c378592cd8f76a795c1fccf1d";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(4).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(4).m_vin.resize(1);
						const std::string pk_str = "2e203ee44fd7bc3a8135072727e20e17bcf0f1ef375624fe939697deb354cec0";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d4cd50baa18fcaee9198b6b8ec49745b438a6f4232cc9bb5e97e0d4c35220996937b7a86cc5d119309a2e8c70b955a4fc16886b23d00b2fda122043bc82e2f03";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "9b580934cf3105d037f30e2ec59114e47bbc5a811a23e6ec9bba38e153b8b340";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(4).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(4).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "e0ee1c292ff6c2352cc87b18797e4a53c4ff0195743d656fe144cec28d814a41";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56495b5ef426f64368a86ec4eebe9dd3fc74b273bc110c68d84d35a8d7f7d6df2f07";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_allmetadata = allmetadata;
						const std::string txid_str = "07940fae97f3d30ed3adf38f4b2c609dc47c062f93e4886c2e806123999dfd51";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(5).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(5).m_vin.resize(1);
						const std::string pk_str = "401fbe90b98a21fb309efa8cb6b863c0a268290ab4017388c090d8ae13fcc412";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "a30b7c8af0c296cd1f23f29e9d114b3af4dd66fa9b203263f19702757225fb9c4b3f5a7400fbee285451c6da65cd1d75f263b176f840c75fdcc9ffa819feb70f";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "1181f568a890d8d5af479297b0d59cc14acf2a7e019e3a5983b4bb89d11df3c6";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(5).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(5).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "10db4fd097fc40c1bd9ee7bfbc41c77418c8647e9ba2e0ed9ba84e0db63f31c4";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649c6a2e06e45eb006d95509e6a8d1f5df533d6e99a6851a9500c64d2de8a7c5a2c";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_allmetadata = allmetadata;
						const std::string txid_str = "07b391910bc9e6c13594cc5ff8f983656ff55b32b553238b9275797dc7fca7b7";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(6).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(6).m_vin.resize(1);
						const std::string pk_str = "3d178b0b30617b4af52a8cffea2a9c7a9a33369f6c8539e2aa5ebcefb3463bc2";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "28f72bd76a8a1246f5689f9889be85970b4676b40a965417ceffa76f9aeb36840dc2e9445da53fe2c3aea69b36e265f1131560a41df8b63a7575407b5f1d4806";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "e080f4f40b5e001ec99b0b805b51350245e9384c947b86ba5c78d6d023f6687e";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(6).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(6).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "bf69ad85ff386d9c3d0b5b98f2ebe3e3f504b48299990840d09c757e3c1980c9";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649f2acc0a51077ffad7d58c081941de566148aee12a08b31a74205db12abd034bd";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_allmetadata = allmetadata;
						const std::string txid_str = "080335963bc17231280e081be17bba94ef723e2833d454b0d261a5e5e428a540";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(7).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(7).m_vin.resize(1);
						const std::string pk_str = "7afef692822b9410c0d346c77c5aade07dacf68c5fa0527f97e9f1d994777c7a";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "40e382a97a4b6c93b5fd97d442c714422ddb07adf82249932652c8f550d3651b6bc021be4831ed98908ad57d2a2cfbc5017c5733b48568c5426437ef11abe50d";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "f2bcd1b293751203297f95c9b2bffedf292f3913364d003662f35fe0b133a598";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(7).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(7).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "c02f62c53c8efa34a2071974c33fa1d9c3272d8583485faec00bf1a2992a0d65";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56498a7786fa98645053574efa5db931cc88922c63dc2f2b9795dd49e56f100bf361";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_allmetadata = allmetadata;
						const std::string txid_str = "08145edee201eae0c6b9f0ef4ec013d83cd0278fe2b2a422e4dd7a41a2e6b301";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(8).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(8).m_vin.resize(1);
						const std::string pk_str = "8b64d8b9a96c824a11a16020ef95f7d9902bebabea087f0c3d16f287f2c166da";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "af640ceeb7b33470a7f9557eeb1d4f0492a2605823a5457c44d2d0342dab78493f948528f4bcc98863dd2203e59734c233dedcbcd364dd3c464b99ce7617ac04";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "2b95205761b14d44acc47ee232cf2a9e790d4049d0879bd4fdb097f5e36c195f";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(8).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(8).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "f41a123e9ff50f9faf8fa3662ec8204d10c50550006228598ff531616c12d700";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649df2c35a8f3c290b1e1bcc397463d0fbc5bc8614e0fc6e3acc727ca7b3903379a";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_allmetadata = allmetadata;
						const std::string txid_str = "085839f770dd19364c743663cb77c997a504d63550e01a4a2c2ffd9d5bbfa4e5";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(9).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(9).m_vin.resize(1);
						const std::string pk_str = "05ebc634b203f7051b9f869f83132b4c507b439fc2c14ab881c7f6c706cd5dd5";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "01e618902095fc5f924c6b4999027c0e48f9c0788016da1775f613b5c6e4212f68cb96ec2b4722a6395110020d60644539ec612bf21de550a74a77d260185006";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "ae5306bf4e6af9ed4b56045a9e26dcf10dadcc9f1312dc82b7773baa21dc6c3b";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(9).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(9).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "734ab69e21168b4ceef91579a663fb6c421e9461623730548fd8af1abc4a511d";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vout.at(0).m_pkh = pkh;
					}
					response_get_transactions_per_page.m_total_number_txs = 45253;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_transactions_per_page";
	cmd["params"]["offset"] = 4;
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["allmetadata"], "564929e20c8efd64930b410b8cd9a68b6a2147d1ff388c55d4237bf952459b7e4b02");
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["txid"], "069e1b1976e9658c98f39864e51c6c9228d9473f2f98370d862df63d38c3b1eb");
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["vin"].at(0)["pk"], "b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015");
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["vin"].at(0)["sign"], "493946c42742b9387789b6e11516ccdd118d949bbd10d0fab2786a565aaf0578ab89cd9ba15275f1a059f78562a274a66cf20fb0ea37a6fdabd48affcbc4ff03");
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["vin"].at(0)["vin_txid"], "433fdd2e27094dd6ad4c0ab56a8a336e44bf3eb5990d7e326892ab805da52865");
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(0)["vout"].at(0)["pkh"], "bc1a237e7d391019891dde86bdee44f086fe843cd5b1a55686cfbef263f1a717");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["allmetadata"], "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39");
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["txid"], "06ae8574b3bcaeb083e493afcf8e07ab644fecb8d27a4596e7f256dd644d070e");
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["vin"].at(0)["pk"], "b4858674fe85ebd18de759374a0ee8fa678f315ca4a32cdd9181c90c2324d78f");
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["vin"].at(0)["sign"], "b59c00aa1e3b7b7301f638efb73e61ffd2d6a10d668c87e813127c04c7737a260da4ad0d1f7b3f16c716729813f3c1216b275c7eae807c89cf309f7f2a6e6800");
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["vin"].at(0)["vin_txid"], "4c3f29db495fdcbbf7ca25c6f243a6aa585e88705ba79fb06810aa21a821875f");
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(1)["vout"].at(0)["pkh"], "accc3b80d4d340efca6cbf9c8956be1bf2f621acd67b6aa81053d396c8470a2b");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["allmetadata"], "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39");
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["txid"], "06e2714cbf649bbec481f02967b1e5a1c87b524ab06548ab4a1425d490fdcfd4");
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["vin"].at(0)["pk"], "52abdf6ce4c0211a3b359ed199539913d8ac351c4ec74e2e2879b3fef83055f4");
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["vin"].at(0)["sign"], "df5b7fa80a7de4417cbc110162a21611355a5948e0db907c47c5f1ec1b5e478d29e16274fff25efd9fa4ba2982ea2288d9f59892a35061e91e9e1d384f8f9300");
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["vin"].at(0)["vin_txid"], "8e936675b927e8c8d7700021eafc5d59e7b388e0137d5ce77188639230c1d0e9");
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(2)["vout"].at(0)["pkh"], "6379e76880c7b12271952b39d7e83f2d587737bbb6c7b39b2740651670618a48");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["allmetadata"], "56496bd3641e9bffc16cccd298dbf9b373b978be370e18692eb59651e717bef4d74f");
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["txid"], "06faba732c3e93ddcfb90e311e638ca017bfaedba5a6eb544e1b9c9b217a8d6b");
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["vin"].at(0)["pk"], "a9d54c5030625e3fcd353b966c483b3b994d0e6ede260110e0030bba31214789");
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["vin"].at(0)["sign"], "d251360b3ad715afff0edbf57b2f43a81999bb0aa86b26c51d1f9a34b58024c08211de209d1a6b9372c17c0583a7a6aefafe08eb4200e4d34abb9f825fae9a05");
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["vin"].at(0)["vin_txid"], "56389dfbaded59c08ee2bc9302759f22aa88de100d6b8b8c2d45ad5303bf4dbb");
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(3)["vout"].at(0)["pkh"], "25c46cc2d5e17852be68bf33954779911fed9b7cbdb48f95b67363eef47396fb");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["allmetadata"], "56490a7142afa71808a96a41a6aeccb2b5c9ea02d0b3736689472bb2433fc80e315b");
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["txid"], "077426406737d142630990992df79bd856a7709c378592cd8f76a795c1fccf1d");
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["vin"].at(0)["pk"], "2e203ee44fd7bc3a8135072727e20e17bcf0f1ef375624fe939697deb354cec0");
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["vin"].at(0)["sign"], "d4cd50baa18fcaee9198b6b8ec49745b438a6f4232cc9bb5e97e0d4c35220996937b7a86cc5d119309a2e8c70b955a4fc16886b23d00b2fda122043bc82e2f03");
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["vin"].at(0)["vin_txid"], "9b580934cf3105d037f30e2ec59114e47bbc5a811a23e6ec9bba38e153b8b340");
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(4)["vout"].at(0)["pkh"], "e0ee1c292ff6c2352cc87b18797e4a53c4ff0195743d656fe144cec28d814a41");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["allmetadata"], "56495b5ef426f64368a86ec4eebe9dd3fc74b273bc110c68d84d35a8d7f7d6df2f07");
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["txid"], "07940fae97f3d30ed3adf38f4b2c609dc47c062f93e4886c2e806123999dfd51");
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["vin"].at(0)["pk"], "401fbe90b98a21fb309efa8cb6b863c0a268290ab4017388c090d8ae13fcc412");
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["vin"].at(0)["sign"], "a30b7c8af0c296cd1f23f29e9d114b3af4dd66fa9b203263f19702757225fb9c4b3f5a7400fbee285451c6da65cd1d75f263b176f840c75fdcc9ffa819feb70f");
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["vin"].at(0)["vin_txid"], "1181f568a890d8d5af479297b0d59cc14acf2a7e019e3a5983b4bb89d11df3c6");
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(5)["vout"].at(0)["pkh"], "10db4fd097fc40c1bd9ee7bfbc41c77418c8647e9ba2e0ed9ba84e0db63f31c4");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["allmetadata"], "5649c6a2e06e45eb006d95509e6a8d1f5df533d6e99a6851a9500c64d2de8a7c5a2c");
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["txid"], "07b391910bc9e6c13594cc5ff8f983656ff55b32b553238b9275797dc7fca7b7");
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["vin"].at(0)["pk"], "3d178b0b30617b4af52a8cffea2a9c7a9a33369f6c8539e2aa5ebcefb3463bc2");
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["vin"].at(0)["sign"], "28f72bd76a8a1246f5689f9889be85970b4676b40a965417ceffa76f9aeb36840dc2e9445da53fe2c3aea69b36e265f1131560a41df8b63a7575407b5f1d4806");
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["vin"].at(0)["vin_txid"], "e080f4f40b5e001ec99b0b805b51350245e9384c947b86ba5c78d6d023f6687e");
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(6)["vout"].at(0)["pkh"], "bf69ad85ff386d9c3d0b5b98f2ebe3e3f504b48299990840d09c757e3c1980c9");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["allmetadata"], "5649f2acc0a51077ffad7d58c081941de566148aee12a08b31a74205db12abd034bd");
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["txid"], "080335963bc17231280e081be17bba94ef723e2833d454b0d261a5e5e428a540");
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["vin"].at(0)["pk"], "7afef692822b9410c0d346c77c5aade07dacf68c5fa0527f97e9f1d994777c7a");
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["vin"].at(0)["sign"], "40e382a97a4b6c93b5fd97d442c714422ddb07adf82249932652c8f550d3651b6bc021be4831ed98908ad57d2a2cfbc5017c5733b48568c5426437ef11abe50d");
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["vin"].at(0)["vin_txid"], "f2bcd1b293751203297f95c9b2bffedf292f3913364d003662f35fe0b133a598");
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(7)["vout"].at(0)["pkh"], "c02f62c53c8efa34a2071974c33fa1d9c3272d8583485faec00bf1a2992a0d65");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["allmetadata"], "56498a7786fa98645053574efa5db931cc88922c63dc2f2b9795dd49e56f100bf361");
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["txid"], "08145edee201eae0c6b9f0ef4ec013d83cd0278fe2b2a422e4dd7a41a2e6b301");
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["vin"].at(0)["pk"], "8b64d8b9a96c824a11a16020ef95f7d9902bebabea087f0c3d16f287f2c166da");
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["vin"].at(0)["sign"], "af640ceeb7b33470a7f9557eeb1d4f0492a2605823a5457c44d2d0342dab78493f948528f4bcc98863dd2203e59734c233dedcbcd364dd3c464b99ce7617ac04");
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["vin"].at(0)["vin_txid"], "2b95205761b14d44acc47ee232cf2a9e790d4049d0879bd4fdb097f5e36c195f");
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(8)["vout"].at(0)["pkh"], "f41a123e9ff50f9faf8fa3662ec8204d10c50550006228598ff531616c12d700");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["allmetadata"], "5649df2c35a8f3c290b1e1bcc397463d0fbc5bc8614e0fc6e3acc727ca7b3903379a");
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["txid"], "085839f770dd19364c743663cb77c997a504d63550e01a4a2c2ffd9d5bbfa4e5");
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["vin"].at(0)["pk"], "05ebc634b203f7051b9f869f83132b4c507b439fc2c14ab881c7f6c706cd5dd5");
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["vin"].at(0)["sign"], "01e618902095fc5f924c6b4999027c0e48f9c0788016da1775f613b5c6e4212f68cb96ec2b4722a6395110020d60644539ec612bf21de550a74a77d260185006");
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["vin"].at(0)["vin_txid"], "ae5306bf4e6af9ed4b56045a9e26dcf10dadcc9f1312dc82b7773baa21dc6c3b");
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["txs"].at(9)["vout"].at(0)["pkh"], "734ab69e21168b4ceef91579a663fb6c421e9461623730548fd8af1abc4a511d");
	}
	EXPECT_EQ(result["result"]["data"]["total_number_txs"], 45253);
}

TEST_F(rpc, get_votings_by_name_or_id) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_votings_by_name_or_id = dynamic_cast<const t_mediator_command_request_get_votings_by_name_or_id&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_votings_by_name_or_id>();
					auto & response_get_votings_by_name_or_id = dynamic_cast<t_mediator_command_response_get_votings_by_name_or_id&>(*response);
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679183050;
						const uint32_t voting_end_time = 1679189050;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						voting_metadata.m_authorization_level = 1;
						voting_metadata.m_question = "Do you prefer option a or b?";
						t_hash_type voting_id;
						const std::string voting_id_str = "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_by_name_or_id.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_by_name_or_id.m_voter_turnout.push_back(std::make_pair(voting_id, 0.0));
						response_get_votings_by_name_or_id.m_is_waiting.push_back(voting_id);
						std::unordered_map<std::string, uint32_t> votings_results;
						votings_results.emplace("option A", 0);
						votings_results.emplace("option B", 0);
						response_get_votings_by_name_or_id.m_votings_results.push_back(std::make_pair(voting_id, votings_results));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079730;
						const uint32_t voting_end_time = 1679183030;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						voting_metadata.m_authorization_level = 1;
						voting_metadata.m_question = "Do you prefer option a or b?";
						t_hash_type voting_id;
						const std::string voting_id_str = "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_by_name_or_id .m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_by_name_or_id.m_is_finished.push_back(std::make_pair(voting_id, false));
						response_get_votings_by_name_or_id.m_voter_turnout.push_back(std::make_pair(voting_id, 57.0));
						std::unordered_map<std::string, uint32_t> votings_results;
						votings_results.emplace("option A", 27);
						votings_results.emplace("option B", 30);
						response_get_votings_by_name_or_id.m_votings_results.push_back(std::make_pair(voting_id, votings_results));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679078630;
						const uint32_t voting_end_time = 1679083130;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						voting_metadata.m_authorization_level = 1;
						voting_metadata.m_question = "Do you prefer option a or b?";
						t_hash_type voting_id;
						const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_by_name_or_id.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_by_name_or_id.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_by_name_or_id.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
						std::unordered_map<std::string, uint32_t> votings_results;
						votings_results.emplace("option A", 57);
						votings_results.emplace("option B", 43);
						response_get_votings_by_name_or_id.m_votings_results.push_back(std::make_pair(voting_id, votings_results));
					}
					response_get_votings_by_name_or_id.m_total_number_votings = 3;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_votings_by_name_or_id";
	cmd["params"]["offset"] = 1;
	cmd["params"]["voting_name_or_id"] = "Voting B";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["end_time"], 1679189050);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["start_time"], 1679183050);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["authorization_level"], 1);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["voting_question"], "Do you prefer option a or b?");
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["votings_result"]["option A"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["votings_result"]["option B"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["status"], "waiting");
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["voter_turnout"], 0.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["voting_id"], "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["end_time"], 1679183030);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["start_time"], 1679079730);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["authorization_level"], 1);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["voting_question"], "Do you prefer option a or b?");
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["votings_result"]["option A"], 27);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["votings_result"]["option B"], 30);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["status"], "active");
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["voter_turnout"], 57.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["voting_id"], "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["end_time"], 1679083130);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["start_time"], 1679078630);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["authorization_level"], 1);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["voting_question"], "Do you prefer option a or b?");
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["votings_result"]["option A"], 57);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["votings_result"]["option B"], 43);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["voting_id"], "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e");
	}
	EXPECT_EQ(result["result"]["data"]["total_number_votings"], 3);
}

TEST_F(rpc, get_latest_votings) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_latest_votings = dynamic_cast<const t_mediator_command_request_get_latest_votings&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_latest_votings>();
					auto & response_get_latest_votings = dynamic_cast<t_mediator_command_response_get_latest_votings&>(*response);
					EXPECT_EQ(request_get_latest_votings.m_amount_votings, 3);
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679183050;
						const uint32_t voting_end_time = 1679189050;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting D";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_votings.m_latest_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_latest_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 0.0));
						response_get_latest_votings.m_is_waiting.push_back(voting_id);
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079730;
						const uint32_t voting_end_time = 1679183030;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting C";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_votings.m_latest_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_latest_votings.m_is_finished.push_back(std::make_pair(voting_id, false));
						response_get_latest_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 57.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079630;
						const uint32_t voting_end_time = 1679093130;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_latest_votings.m_latest_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_latest_votings.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_latest_votings.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_latest_votings";
	cmd["params"]["number_votings"] = 3;
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(0)["end_time"], 1679189050);
		EXPECT_EQ(result["result"]["data"].at(0)["name"], "Voting D");
		EXPECT_EQ(result["result"]["data"].at(0)["start_time"], 1679183050);
		EXPECT_EQ(result["result"]["data"].at(0)["status"], "waiting");
		EXPECT_EQ(result["result"]["data"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(0)["voter_turnout"], 0.0);
		EXPECT_EQ(result["result"]["data"].at(0)["voting_id"], "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(1)["end_time"], 1679183030);
		EXPECT_EQ(result["result"]["data"].at(1)["name"], "Voting C");
		EXPECT_EQ(result["result"]["data"].at(1)["start_time"], 1679079730);
		EXPECT_EQ(result["result"]["data"].at(1)["status"], "active");
		EXPECT_EQ(result["result"]["data"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(1)["voter_turnout"], 57.0);
		EXPECT_EQ(result["result"]["data"].at(1)["voting_id"], "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"].at(2)["end_time"], 1679093130);
		EXPECT_EQ(result["result"]["data"].at(2)["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"].at(2)["start_time"], 1679079630);
		EXPECT_EQ(result["result"]["data"].at(2)["status"], "finished");
		EXPECT_EQ(result["result"]["data"].at(2)["type"], 0);
		EXPECT_EQ(result["result"]["data"].at(2)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"].at(2)["voting_id"], "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
}

TEST_F(rpc, get_votings_per_page) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_votings_per_page = dynamic_cast<const t_mediator_command_request_get_votings_per_page&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_votings_per_page>();
					auto & response_get_votings_per_page = dynamic_cast<t_mediator_command_response_get_votings_per_page&>(*response);
					EXPECT_EQ(request_get_votings_per_page.m_offset, 3);
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679183050;
						const uint32_t voting_end_time = 1679189050;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting D";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 0.0));
						response_get_votings_per_page.m_is_waiting.push_back(voting_id);
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079730;
						const uint32_t voting_end_time = 1679183030;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting C";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, false));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 57.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079630;
						const uint32_t voting_end_time = 1679093130;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079620;
						const uint32_t voting_end_time = 1679093120;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "a096de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079610;
						const uint32_t voting_end_time = 1679093110;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "aa96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079600;
						const uint32_t voting_end_time = 1679093100;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "bb96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079590;
						const uint32_t voting_end_time = 1679093090;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "cc96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079580;
						const uint32_t voting_end_time = 1679093080;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "dd96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079570;
						const uint32_t voting_end_time = 1679093070;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "ee96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079560;
						const uint32_t voting_end_time = 1679093060;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting A";
						voting_metadata.m_voting_type = 0;
						t_hash_type voting_id;
						const std::string voting_id_str = "ff96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_votings_per_page.m_votings.push_back(std::make_pair(voting_id, voting_metadata));
						response_get_votings_per_page.m_is_finished.push_back(std::make_pair(voting_id, true));
						response_get_votings_per_page.m_voter_turnout.push_back(std::make_pair(voting_id, 100.0));
					}
					response_get_votings_per_page.m_total_number_votings = 150;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_votings_per_page";
	cmd["params"]["offset"] = 3;
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["end_time"], 1679189050);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["name"], "Voting D");
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["start_time"], 1679183050);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["status"], "waiting");
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["voter_turnout"], 0.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(0)["voting_id"], "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["end_time"], 1679183030);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["name"], "Voting C");
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["start_time"], 1679079730);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["status"], "active");
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["voter_turnout"], 57.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(1)["voting_id"], "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["end_time"], 1679093130);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["start_time"], 1679079630);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(2)["voting_id"], "f996de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(3)["end_time"], 1679093120);
		EXPECT_EQ(result["result"]["data"]["votings"].at(3)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"]["votings"].at(3)["start_time"], 1679079620);
		EXPECT_EQ(result["result"]["data"]["votings"].at(3)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(3)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(3)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(3)["voting_id"], "a096de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(4)["end_time"], 1679093110);
		EXPECT_EQ(result["result"]["data"]["votings"].at(4)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"]["votings"].at(4)["start_time"], 1679079610);
		EXPECT_EQ(result["result"]["data"]["votings"].at(4)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(4)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(4)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(4)["voting_id"], "aa96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(5)["end_time"], 1679093100);
		EXPECT_EQ(result["result"]["data"]["votings"].at(5)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"]["votings"].at(5)["start_time"], 1679079600);
		EXPECT_EQ(result["result"]["data"]["votings"].at(5)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(5)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(5)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(5)["voting_id"], "bb96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(6)["end_time"], 1679093090);
		EXPECT_EQ(result["result"]["data"]["votings"].at(6)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"]["votings"].at(6)["start_time"], 1679079590);
		EXPECT_EQ(result["result"]["data"]["votings"].at(6)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(6)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(6)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(6)["voting_id"], "cc96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(7)["end_time"], 1679093080);
		EXPECT_EQ(result["result"]["data"]["votings"].at(7)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"]["votings"].at(7)["start_time"], 1679079580);
		EXPECT_EQ(result["result"]["data"]["votings"].at(7)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(7)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(7)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(7)["voting_id"], "dd96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(8)["end_time"], 1679093070);
		EXPECT_EQ(result["result"]["data"]["votings"].at(8)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"]["votings"].at(8)["start_time"], 1679079570);
		EXPECT_EQ(result["result"]["data"]["votings"].at(8)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(8)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(8)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(8)["voting_id"], "ee96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["votings"].at(9)["end_time"], 1679093060);
		EXPECT_EQ(result["result"]["data"]["votings"].at(9)["name"], "Voting A");
		EXPECT_EQ(result["result"]["data"]["votings"].at(9)["start_time"], 1679079560);
		EXPECT_EQ(result["result"]["data"]["votings"].at(9)["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["votings"].at(9)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(9)["voter_turnout"], 100.0);
		EXPECT_EQ(result["result"]["data"]["votings"].at(9)["voting_id"], "ff96de90cfc080d11d18ce5bf392b0714e9c6bc90426f964dc076976d2451810");
	}
	EXPECT_EQ(result["result"]["data"]["total_number_votings"], 150);
}

TEST_F(rpc, get_transactions_from_block_per_page) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_transactions_per_page = dynamic_cast<const t_mediator_command_request_get_txs_from_block_per_page&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_txs_from_block_per_page>();
					auto & response_get_transactions_per_page = dynamic_cast<t_mediator_command_response_get_txs_from_block_per_page&>(*response);
					EXPECT_EQ(request_get_transactions_per_page.m_offset, 5);
					const std::string blockid_as_str = "3ecd209c7d76071f63d44fdb430bc26f93bf677af7dc380d65be68355b6e62d2";
					t_hash_type blockid;
					if(blockid_as_str.size()!=blockid.size()*2) throw std::invalid_argument("Bad blockid size");
					const auto ret = sodium_hex2bin(blockid.data(), blockid.size(),
					                                blockid_as_str.data(), blockid_as_str.size(),
					                                nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_transactions_per_page.m_block_id, blockid);
					response_get_transactions_per_page.m_transactions.resize(10);
					{
						const std::string allmetadata_str = "564929e20c8efd64930b410b8cd9a68b6a2147d1ff388c55d4237bf952459b7e4b02";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_allmetadata = allmetadata;
						const std::string txid_str = "069e1b1976e9658c98f39864e51c6c9228d9473f2f98370d862df63d38c3b1eb";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(0).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(0).m_vin.resize(1);
						const std::string pk_str = "b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "493946c42742b9387789b6e11516ccdd118d949bbd10d0fab2786a565aaf0578ab89cd9ba15275f1a059f78562a274a66cf20fb0ea37a6fdabd48affcbc4ff03";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "433fdd2e27094dd6ad4c0ab56a8a336e44bf3eb5990d7e326892ab805da52865";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(0).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(0).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "bc1a237e7d391019891dde86bdee44f086fe843cd5b1a55686cfbef263f1a717";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(0).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_allmetadata = allmetadata;
						const std::string txid_str = "06ae8574b3bcaeb083e493afcf8e07ab644fecb8d27a4596e7f256dd644d070e";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(1).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(1).m_vin.resize(1);
						const std::string pk_str = "b4858674fe85ebd18de759374a0ee8fa678f315ca4a32cdd9181c90c2324d78f";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "b59c00aa1e3b7b7301f638efb73e61ffd2d6a10d668c87e813127c04c7737a260da4ad0d1f7b3f16c716729813f3c1216b275c7eae807c89cf309f7f2a6e6800";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "4c3f29db495fdcbbf7ca25c6f243a6aa585e88705ba79fb06810aa21a821875f";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(1).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(1).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "accc3b80d4d340efca6cbf9c8956be1bf2f621acd67b6aa81053d396c8470a2b";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(1).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_allmetadata = allmetadata;
						const std::string txid_str = "06e2714cbf649bbec481f02967b1e5a1c87b524ab06548ab4a1425d490fdcfd4";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(2).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(2).m_vin.resize(1);
						const std::string pk_str = "52abdf6ce4c0211a3b359ed199539913d8ac351c4ec74e2e2879b3fef83055f4";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "df5b7fa80a7de4417cbc110162a21611355a5948e0db907c47c5f1ec1b5e478d29e16274fff25efd9fa4ba2982ea2288d9f59892a35061e91e9e1d384f8f9300";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "8e936675b927e8c8d7700021eafc5d59e7b388e0137d5ce77188639230c1d0e9";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(2).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(2).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "6379e76880c7b12271952b39d7e83f2d587737bbb6c7b39b2740651670618a48";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(2).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56496bd3641e9bffc16cccd298dbf9b373b978be370e18692eb59651e717bef4d74f";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_allmetadata = allmetadata;
						const std::string txid_str = "06faba732c3e93ddcfb90e311e638ca017bfaedba5a6eb544e1b9c9b217a8d6b";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(3).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(3).m_vin.resize(1);
						const std::string pk_str = "a9d54c5030625e3fcd353b966c483b3b994d0e6ede260110e0030bba31214789";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d251360b3ad715afff0edbf57b2f43a81999bb0aa86b26c51d1f9a34b58024c08211de209d1a6b9372c17c0583a7a6aefafe08eb4200e4d34abb9f825fae9a05";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "56389dfbaded59c08ee2bc9302759f22aa88de100d6b8b8c2d45ad5303bf4dbb";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(3).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(3).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "25c46cc2d5e17852be68bf33954779911fed9b7cbdb48f95b67363eef47396fb";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(3).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56490a7142afa71808a96a41a6aeccb2b5c9ea02d0b3736689472bb2433fc80e315b";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_allmetadata = allmetadata;
						const std::string txid_str = "077426406737d142630990992df79bd856a7709c378592cd8f76a795c1fccf1d";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(4).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(4).m_vin.resize(1);
						const std::string pk_str = "2e203ee44fd7bc3a8135072727e20e17bcf0f1ef375624fe939697deb354cec0";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "d4cd50baa18fcaee9198b6b8ec49745b438a6f4232cc9bb5e97e0d4c35220996937b7a86cc5d119309a2e8c70b955a4fc16886b23d00b2fda122043bc82e2f03";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "9b580934cf3105d037f30e2ec59114e47bbc5a811a23e6ec9bba38e153b8b340";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(4).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(4).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "e0ee1c292ff6c2352cc87b18797e4a53c4ff0195743d656fe144cec28d814a41";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(4).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56495b5ef426f64368a86ec4eebe9dd3fc74b273bc110c68d84d35a8d7f7d6df2f07";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_allmetadata = allmetadata;
						const std::string txid_str = "07940fae97f3d30ed3adf38f4b2c609dc47c062f93e4886c2e806123999dfd51";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(5).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(5).m_vin.resize(1);
						const std::string pk_str = "401fbe90b98a21fb309efa8cb6b863c0a268290ab4017388c090d8ae13fcc412";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "a30b7c8af0c296cd1f23f29e9d114b3af4dd66fa9b203263f19702757225fb9c4b3f5a7400fbee285451c6da65cd1d75f263b176f840c75fdcc9ffa819feb70f";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "1181f568a890d8d5af479297b0d59cc14acf2a7e019e3a5983b4bb89d11df3c6";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(5).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(5).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "10db4fd097fc40c1bd9ee7bfbc41c77418c8647e9ba2e0ed9ba84e0db63f31c4";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(5).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649c6a2e06e45eb006d95509e6a8d1f5df533d6e99a6851a9500c64d2de8a7c5a2c";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_allmetadata = allmetadata;
						const std::string txid_str = "07b391910bc9e6c13594cc5ff8f983656ff55b32b553238b9275797dc7fca7b7";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(6).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(6).m_vin.resize(1);
						const std::string pk_str = "3d178b0b30617b4af52a8cffea2a9c7a9a33369f6c8539e2aa5ebcefb3463bc2";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "28f72bd76a8a1246f5689f9889be85970b4676b40a965417ceffa76f9aeb36840dc2e9445da53fe2c3aea69b36e265f1131560a41df8b63a7575407b5f1d4806";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "e080f4f40b5e001ec99b0b805b51350245e9384c947b86ba5c78d6d023f6687e";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(6).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(6).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "bf69ad85ff386d9c3d0b5b98f2ebe3e3f504b48299990840d09c757e3c1980c9";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(6).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649f2acc0a51077ffad7d58c081941de566148aee12a08b31a74205db12abd034bd";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_allmetadata = allmetadata;
						const std::string txid_str = "080335963bc17231280e081be17bba94ef723e2833d454b0d261a5e5e428a540";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(7).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(7).m_vin.resize(1);
						const std::string pk_str = "7afef692822b9410c0d346c77c5aade07dacf68c5fa0527f97e9f1d994777c7a";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "40e382a97a4b6c93b5fd97d442c714422ddb07adf82249932652c8f550d3651b6bc021be4831ed98908ad57d2a2cfbc5017c5733b48568c5426437ef11abe50d";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "f2bcd1b293751203297f95c9b2bffedf292f3913364d003662f35fe0b133a598";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(7).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(7).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "c02f62c53c8efa34a2071974c33fa1d9c3272d8583485faec00bf1a2992a0d65";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(7).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "56498a7786fa98645053574efa5db931cc88922c63dc2f2b9795dd49e56f100bf361";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_allmetadata = allmetadata;
						const std::string txid_str = "08145edee201eae0c6b9f0ef4ec013d83cd0278fe2b2a422e4dd7a41a2e6b301";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(8).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(8).m_vin.resize(1);
						const std::string pk_str = "8b64d8b9a96c824a11a16020ef95f7d9902bebabea087f0c3d16f287f2c166da";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "af640ceeb7b33470a7f9557eeb1d4f0492a2605823a5457c44d2d0342dab78493f948528f4bcc98863dd2203e59734c233dedcbcd364dd3c464b99ce7617ac04";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "2b95205761b14d44acc47ee232cf2a9e790d4049d0879bd4fdb097f5e36c195f";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(8).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(8).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "f41a123e9ff50f9faf8fa3662ec8204d10c50550006228598ff531616c12d700";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(8).m_vout.at(0).m_pkh = pkh;
					}
					{
						const std::string allmetadata_str = "5649df2c35a8f3c290b1e1bcc397463d0fbc5bc8614e0fc6e3acc727ca7b3903379a";
						std::vector<unsigned char> allmetadata;
						allmetadata.resize(allmetadata_str.size()/2);
						if(allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
						int ret = 1;
						ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
											allmetadata_str.data(), allmetadata_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_allmetadata = allmetadata;
						const std::string txid_str = "085839f770dd19364c743663cb77c997a504d63550e01a4a2c2ffd9d5bbfa4e5";
						t_hash_type txid;
						if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
						ret = sodium_hex2bin(txid.data(), txid.size(),
											txid_str.data(), txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_txid = txid;
						response_get_transactions_per_page.m_transactions.at(9).m_type = t_transactiontype::add_secret_vote;
						response_get_transactions_per_page.m_transactions.at(9).m_vin.resize(1);
						const std::string pk_str = "05ebc634b203f7051b9f869f83132b4c507b439fc2c14ab881c7f6c706cd5dd5";
						t_public_key_type pk;
						if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
						ret = sodium_hex2bin(pk.data(), pk.size(),
											pk_str.data(), pk_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vin.at(0).m_pk = pk;
						const std::string sign_str = "01e618902095fc5f924c6b4999027c0e48f9c0788016da1775f613b5c6e4212f68cb96ec2b4722a6395110020d60644539ec612bf21de550a74a77d260185006";
						t_signature_type sign;
						if(sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size");
						ret = sodium_hex2bin(sign.data(), sign.size(),
											sign_str.data(), sign_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vin.at(0).m_sign = sign;
						const std::string vin_txid_str = "ae5306bf4e6af9ed4b56045a9e26dcf10dadcc9f1312dc82b7773baa21dc6c3b";
						t_hash_type vin_txid;
						if(vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size");
						ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
											vin_txid_str.data(), vin_txid_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vin.at(0).m_txid = vin_txid;
						response_get_transactions_per_page.m_transactions.at(9).m_vout.resize(1);
						response_get_transactions_per_page.m_transactions.at(9).m_vout.at(0).m_amount = 1;
						const std::string pkh_str = "734ab69e21168b4ceef91579a663fb6c421e9461623730548fd8af1abc4a511d";
						t_hash_type pkh;
						if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
						ret = sodium_hex2bin(pkh.data(), pkh.size(),
											pkh_str.data(), pkh_str.size(),
											nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						response_get_transactions_per_page.m_transactions.at(9).m_vout.at(0).m_pkh = pkh;
					}
					response_get_transactions_per_page.m_number_txs = 100;
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_transactions_from_block_per_page";
	cmd["params"]["offset"] = 5;
	cmd["params"]["block_id"] = "3ecd209c7d76071f63d44fdb430bc26f93bf677af7dc380d65be68355b6e62d2";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["allmetadata"], "564929e20c8efd64930b410b8cd9a68b6a2147d1ff388c55d4237bf952459b7e4b02");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["txid"], "069e1b1976e9658c98f39864e51c6c9228d9473f2f98370d862df63d38c3b1eb");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["vin"].at(0)["pk"], "b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["vin"].at(0)["sign"], "493946c42742b9387789b6e11516ccdd118d949bbd10d0fab2786a565aaf0578ab89cd9ba15275f1a059f78562a274a66cf20fb0ea37a6fdabd48affcbc4ff03");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["vin"].at(0)["vin_txid"], "433fdd2e27094dd6ad4c0ab56a8a336e44bf3eb5990d7e326892ab805da52865");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(0)["vout"].at(0)["pkh"], "bc1a237e7d391019891dde86bdee44f086fe843cd5b1a55686cfbef263f1a717");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["allmetadata"], "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["txid"], "06ae8574b3bcaeb083e493afcf8e07ab644fecb8d27a4596e7f256dd644d070e");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["vin"].at(0)["pk"], "b4858674fe85ebd18de759374a0ee8fa678f315ca4a32cdd9181c90c2324d78f");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["vin"].at(0)["sign"], "b59c00aa1e3b7b7301f638efb73e61ffd2d6a10d668c87e813127c04c7737a260da4ad0d1f7b3f16c716729813f3c1216b275c7eae807c89cf309f7f2a6e6800");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["vin"].at(0)["vin_txid"], "4c3f29db495fdcbbf7ca25c6f243a6aa585e88705ba79fb06810aa21a821875f");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(1)["vout"].at(0)["pkh"], "accc3b80d4d340efca6cbf9c8956be1bf2f621acd67b6aa81053d396c8470a2b");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["allmetadata"], "5649edbf5ea6fceb612d482d1fc4161248f5c9524deacdd2d75a7a554417c096fc39");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["txid"], "06e2714cbf649bbec481f02967b1e5a1c87b524ab06548ab4a1425d490fdcfd4");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["vin"].at(0)["pk"], "52abdf6ce4c0211a3b359ed199539913d8ac351c4ec74e2e2879b3fef83055f4");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["vin"].at(0)["sign"], "df5b7fa80a7de4417cbc110162a21611355a5948e0db907c47c5f1ec1b5e478d29e16274fff25efd9fa4ba2982ea2288d9f59892a35061e91e9e1d384f8f9300");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["vin"].at(0)["vin_txid"], "8e936675b927e8c8d7700021eafc5d59e7b388e0137d5ce77188639230c1d0e9");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(2)["vout"].at(0)["pkh"], "6379e76880c7b12271952b39d7e83f2d587737bbb6c7b39b2740651670618a48");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["allmetadata"], "56496bd3641e9bffc16cccd298dbf9b373b978be370e18692eb59651e717bef4d74f");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["txid"], "06faba732c3e93ddcfb90e311e638ca017bfaedba5a6eb544e1b9c9b217a8d6b");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["vin"].at(0)["pk"], "a9d54c5030625e3fcd353b966c483b3b994d0e6ede260110e0030bba31214789");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["vin"].at(0)["sign"], "d251360b3ad715afff0edbf57b2f43a81999bb0aa86b26c51d1f9a34b58024c08211de209d1a6b9372c17c0583a7a6aefafe08eb4200e4d34abb9f825fae9a05");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["vin"].at(0)["vin_txid"], "56389dfbaded59c08ee2bc9302759f22aa88de100d6b8b8c2d45ad5303bf4dbb");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(3)["vout"].at(0)["pkh"], "25c46cc2d5e17852be68bf33954779911fed9b7cbdb48f95b67363eef47396fb");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["allmetadata"], "56490a7142afa71808a96a41a6aeccb2b5c9ea02d0b3736689472bb2433fc80e315b");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["txid"], "077426406737d142630990992df79bd856a7709c378592cd8f76a795c1fccf1d");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["vin"].at(0)["pk"], "2e203ee44fd7bc3a8135072727e20e17bcf0f1ef375624fe939697deb354cec0");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["vin"].at(0)["sign"], "d4cd50baa18fcaee9198b6b8ec49745b438a6f4232cc9bb5e97e0d4c35220996937b7a86cc5d119309a2e8c70b955a4fc16886b23d00b2fda122043bc82e2f03");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["vin"].at(0)["vin_txid"], "9b580934cf3105d037f30e2ec59114e47bbc5a811a23e6ec9bba38e153b8b340");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(4)["vout"].at(0)["pkh"], "e0ee1c292ff6c2352cc87b18797e4a53c4ff0195743d656fe144cec28d814a41");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["allmetadata"], "56495b5ef426f64368a86ec4eebe9dd3fc74b273bc110c68d84d35a8d7f7d6df2f07");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["txid"], "07940fae97f3d30ed3adf38f4b2c609dc47c062f93e4886c2e806123999dfd51");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["vin"].at(0)["pk"], "401fbe90b98a21fb309efa8cb6b863c0a268290ab4017388c090d8ae13fcc412");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["vin"].at(0)["sign"], "a30b7c8af0c296cd1f23f29e9d114b3af4dd66fa9b203263f19702757225fb9c4b3f5a7400fbee285451c6da65cd1d75f263b176f840c75fdcc9ffa819feb70f");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["vin"].at(0)["vin_txid"], "1181f568a890d8d5af479297b0d59cc14acf2a7e019e3a5983b4bb89d11df3c6");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(5)["vout"].at(0)["pkh"], "10db4fd097fc40c1bd9ee7bfbc41c77418c8647e9ba2e0ed9ba84e0db63f31c4");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["allmetadata"], "5649c6a2e06e45eb006d95509e6a8d1f5df533d6e99a6851a9500c64d2de8a7c5a2c");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["txid"], "07b391910bc9e6c13594cc5ff8f983656ff55b32b553238b9275797dc7fca7b7");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["vin"].at(0)["pk"], "3d178b0b30617b4af52a8cffea2a9c7a9a33369f6c8539e2aa5ebcefb3463bc2");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["vin"].at(0)["sign"], "28f72bd76a8a1246f5689f9889be85970b4676b40a965417ceffa76f9aeb36840dc2e9445da53fe2c3aea69b36e265f1131560a41df8b63a7575407b5f1d4806");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["vin"].at(0)["vin_txid"], "e080f4f40b5e001ec99b0b805b51350245e9384c947b86ba5c78d6d023f6687e");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(6)["vout"].at(0)["pkh"], "bf69ad85ff386d9c3d0b5b98f2ebe3e3f504b48299990840d09c757e3c1980c9");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["allmetadata"], "5649f2acc0a51077ffad7d58c081941de566148aee12a08b31a74205db12abd034bd");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["txid"], "080335963bc17231280e081be17bba94ef723e2833d454b0d261a5e5e428a540");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["vin"].at(0)["pk"], "7afef692822b9410c0d346c77c5aade07dacf68c5fa0527f97e9f1d994777c7a");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["vin"].at(0)["sign"], "40e382a97a4b6c93b5fd97d442c714422ddb07adf82249932652c8f550d3651b6bc021be4831ed98908ad57d2a2cfbc5017c5733b48568c5426437ef11abe50d");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["vin"].at(0)["vin_txid"], "f2bcd1b293751203297f95c9b2bffedf292f3913364d003662f35fe0b133a598");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(7)["vout"].at(0)["pkh"], "c02f62c53c8efa34a2071974c33fa1d9c3272d8583485faec00bf1a2992a0d65");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["allmetadata"], "56498a7786fa98645053574efa5db931cc88922c63dc2f2b9795dd49e56f100bf361");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["txid"], "08145edee201eae0c6b9f0ef4ec013d83cd0278fe2b2a422e4dd7a41a2e6b301");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["vin"].at(0)["pk"], "8b64d8b9a96c824a11a16020ef95f7d9902bebabea087f0c3d16f287f2c166da");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["vin"].at(0)["sign"], "af640ceeb7b33470a7f9557eeb1d4f0492a2605823a5457c44d2d0342dab78493f948528f4bcc98863dd2203e59734c233dedcbcd364dd3c464b99ce7617ac04");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["vin"].at(0)["vin_txid"], "2b95205761b14d44acc47ee232cf2a9e790d4049d0879bd4fdb097f5e36c195f");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(8)["vout"].at(0)["pkh"], "f41a123e9ff50f9faf8fa3662ec8204d10c50550006228598ff531616c12d700");
	}
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["allmetadata"], "5649df2c35a8f3c290b1e1bcc397463d0fbc5bc8614e0fc6e3acc727ca7b3903379a");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["txid"], "085839f770dd19364c743663cb77c997a504d63550e01a4a2c2ffd9d5bbfa4e5");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["type"], 0);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["vin"].at(0)["pk"], "05ebc634b203f7051b9f869f83132b4c507b439fc2c14ab881c7f6c706cd5dd5");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["vin"].at(0)["sign"], "01e618902095fc5f924c6b4999027c0e48f9c0788016da1775f613b5c6e4212f68cb96ec2b4722a6395110020d60644539ec612bf21de550a74a77d260185006");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["vin"].at(0)["vin_txid"], "ae5306bf4e6af9ed4b56045a9e26dcf10dadcc9f1312dc82b7773baa21dc6c3b");
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["vout"].at(0)["amount"], 1);
		EXPECT_EQ(result["result"]["data"]["transactions_from_block"].at(9)["vout"].at(0)["pkh"], "734ab69e21168b4ceef91579a663fb6c421e9461623730548fd8af1abc4a511d");
	}
	EXPECT_EQ(result["result"]["data"]["number_transactions_from_block"], 100);
}

TEST_F(rpc, get_block_signatures_and_miners_public_keys_per_page) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_sign_and_pk_miner = dynamic_cast<const t_mediator_command_request_get_block_signatures_and_pks_miners_per_page&>(request);
					EXPECT_EQ(request_get_sign_and_pk_miner.m_offset, 1);
					response = std::make_unique<t_mediator_command_response_get_block_signatures_and_pks_miners_per_page>();
					auto & response_get_sign_and_pk_miner = dynamic_cast<t_mediator_command_response_get_block_signatures_and_pks_miners_per_page&>(*response);
					t_hash_type block_id;
					const std::string block_id_str = "570530f61eaa55c9b63b05b6b410c23c9ef52af1f6108e1e8021986eab1d79af";
					if(block_id_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad block_id size");
					int ret = 1;
					ret = sodium_hex2bin(block_id.data(), block_id.size(),
										block_id_str.data(), block_id_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					EXPECT_EQ(request_get_sign_and_pk_miner.m_block_id, block_id);
					response_get_sign_and_pk_miner.m_number_signatures = 1;
					t_public_key_type pk;
					const std::string pk_str = "f1a8d7ca6a473db7c66ceb79d58b54b00526d129c46bf3bcb1ba745b56dea3a6";
					if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										pk_str.data(), pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					t_signature_type signature;
					const std::string signature_str = "439a6c99a9ca67487e8f2840fb716d7d72bb2d86f533c218c975e6a5526c795523801da2c9a3b272fc4ad11c3f600ed75594e60c4cd0ab02196de90f62faf00f";
					if(signature_str.size()!=signature.size()*2) throw std::invalid_argument("Bad signature size");
					ret = sodium_hex2bin(signature.data(), signature.size(),
										signature_str.data(), signature_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_sign_and_pk_miner.m_signatures_and_pks.push_back(std::make_pair(signature, pk));
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_block_signatures_and_miners_public_keys_per_page";
	cmd["params"]["offset"] = 1;
	cmd["params"]["block_id"] = "570530f61eaa55c9b63b05b6b410c23c9ef52af1f6108e1e8021986eab1d79af";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["number_signatures_from_block"], 1);
	EXPECT_EQ(result["result"]["data"]["signatures_and_public_keys"].at(0)["public_key"], "f1a8d7ca6a473db7c66ceb79d58b54b00526d129c46bf3bcb1ba745b56dea3a6");
	EXPECT_EQ(result["result"]["data"]["signatures_and_public_keys"].at(0)["signature"], "439a6c99a9ca67487e8f2840fb716d7d72bb2d86f533c218c975e6a5526c795523801da2c9a3b272fc4ad11c3f600ed75594e60c4cd0ab02196de90f62faf00f");
}



TEST_F(rpc, get_tx_with_parse_metadata_from_auth_voter) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_tx = dynamic_cast<const t_mediator_command_request_get_tx&>(request);
					response = std::make_unique<t_mediator_command_response_get_tx>();
					auto & response_get_tx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
					const std::string tx_allmetadata_str = "434fb15d6d5ef8ea4eb52c98fc7599483f6330067f6de7edb754fb9bb6013bcb879d414c00000001504bfec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24";
					std::vector<unsigned char> allmetadata;
					allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					int ret = 1;
					ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_allmetadata = allmetadata;
					const std::string tx_txid_str = "ef99e1a8477216e858a2ce4f8489d7e1fbbfe5379246f2c7a03bd523dd1e16f0";
					t_hash_type txid;
					if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_txid = txid;
					EXPECT_EQ(request_get_tx.m_txid, txid);
					response_get_tx.m_transaction.m_type = t_transactiontype::authorize_voter;
					const std::string tx_vin_pk_str = "530aa8149815decb979d5e11793bef932d340d5be81a1b7b11e383bbc6aa9f4b";
					t_public_key_type pk;
					if(tx_vin_pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.resize(1);
					response_get_tx.m_transaction.m_vin.at(0).m_pk = pk;
					const std::string tx_vin_sign_str = "3341a07f96517eac8a2d6291ed5c66f05e18f4dd729ba4bf35b02691ce234be32af02ff64249377d31c02bd336a7a5e60cb18848b0fddbe566779891e4041400";
					t_signature_type sign;
					if(tx_vin_sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(sign.data(), sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_sign = sign;
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					t_hash_type vin_txid;
					if(tx_vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_txid = vin_txid;
					response_get_tx.m_transaction.m_vout.resize(1);
					response_get_tx.m_transaction.m_vout.at(0).m_amount = 0;
					const std::string tx_vout_pkh_str = "5acf6f1a8a6b483c45b36a1d4d4eb8a18c30311ef0e2d6789c4ac08c6ff92be7";
					t_hash_type pkh;
					if(tx_vout_pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size from tx");
					ret = sodium_hex2bin(pkh.data(), pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vout.at(0).m_pkh = pkh;
					assert(response != nullptr);
					return response;
	});
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_tx_with_parse_metadata";
	cmd["params"]["txid"] = "ef99e1a8477216e858a2ce4f8489d7e1fbbfe5379246f2c7a03bd523dd1e16f0";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["transaction"]["allmetadata"], "434fb15d6d5ef8ea4eb52c98fc7599483f6330067f6de7edb754fb9bb6013bcb879d414c00000001504bfec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24");
	EXPECT_EQ(result["result"]["data"]["transaction"]["txid"], "ef99e1a8477216e858a2ce4f8489d7e1fbbfe5379246f2c7a03bd523dd1e16f0");
	EXPECT_EQ(result["result"]["data"]["transaction"]["type"], 6);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["pk"], "530aa8149815decb979d5e11793bef932d340d5be81a1b7b11e383bbc6aa9f4b");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["sign"], "3341a07f96517eac8a2d6291ed5c66f05e18f4dd729ba4bf35b02691ce234be32af02ff64249377d31c02bd336a7a5e60cb18848b0fddbe566779891e4041400");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["amount"], 0);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["pkh"], "5acf6f1a8a6b483c45b36a1d4d4eb8a18c30311ef0e2d6789c4ac08c6ff92be7");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Authorization_level"], 1);
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Authorized_person_pk"], "fec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Voting_group/Organizer_pk"], "b15d6d5ef8ea4eb52c98fc7599483f6330067f6de7edb754fb9bb6013bcb879d");
}

TEST_F(rpc, get_tx_with_parse_metadata_from_create_voting) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_tx = dynamic_cast<const t_mediator_command_request_get_tx&>(request);
					response = std::make_unique<t_mediator_command_response_get_tx>();
					auto & response_get_tx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
					const std::string tx_allmetadata_str = "51531c446f20796f7520707265666572206f7074696f6e2061206f7220623f4f5001614f500162564e0a566f74696e6720313236414c000000014e43000142450000000f5354642e86c75654004e4f7add94a2";
					std::vector<unsigned char> allmetadata;
					allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					int ret = 1;
					ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_allmetadata = allmetadata;
					const std::string tx_txid_str = "a5cc7be40c00077fd846848c237087f2b4457736151671ea5afee3789a151368";
					t_hash_type txid;
					if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_txid = txid;
					EXPECT_EQ(request_get_tx.m_txid, txid);
					response_get_tx.m_transaction.m_type = t_transactiontype::create_voting;
					const std::string tx_vin_pk_str = "b15d6d5ef8ea4eb52c98fc7599483f6330067f6de7edb754fb9bb6013bcb879d";
					t_public_key_type pk;
					if(tx_vin_pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.resize(1);
					response_get_tx.m_transaction.m_vin.at(0).m_pk = pk;
					const std::string tx_vin_sign_str = "7e4878779a29116d87c459cb055658a4e9b1fee5bb8386bc1f7faa19aad42ed3320d04a5266cba9a9f926200cf3a7b0e8d0da7c577e908c20b80112e847f7605";
					t_signature_type sign;
					if(tx_vin_sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(sign.data(), sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_sign = sign;
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					t_hash_type vin_txid;
					if(tx_vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_txid = vin_txid;
					assert(response != nullptr);
					return response;
	});
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_tx_with_parse_metadata";
	cmd["params"]["txid"] = "a5cc7be40c00077fd846848c237087f2b4457736151671ea5afee3789a151368";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["transaction"]["allmetadata"], "51531c446f20796f7520707265666572206f7074696f6e2061206f7220623f4f5001614f500162564e0a566f74696e6720313236414c000000014e43000142450000000f5354642e86c75654004e4f7add94a2");
	EXPECT_EQ(result["result"]["data"]["transaction"]["txid"], "a5cc7be40c00077fd846848c237087f2b4457736151671ea5afee3789a151368");
	EXPECT_EQ(result["result"]["data"]["transaction"]["type"], 7);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["pk"], "b15d6d5ef8ea4eb52c98fc7599483f6330067f6de7edb754fb9bb6013bcb879d");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["sign"], "7e4878779a29116d87c459cb055658a4e9b1fee5bb8386bc1f7faa19aad42ed3320d04a5266cba9a9f926200cf3a7b0e8d0da7c577e908c20b80112e847f7605");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_TRUE(result["result"]["data"]["transaction"]["vout"].empty());
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Authorization_level"], 1);
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["End_voting_date"], 1680770909);
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Number_of_choice"], 1);
	const auto options = result["result"]["data"]["parsed_metadata"]["Options"];
	EXPECT_NE(std::find(options.cbegin(), options.cend(), "a"), options.cend());
	EXPECT_NE(std::find(options.cbegin(), options.cend(), "b"), options.cend());
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Question"], "Do you prefer option a or b?");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Start_voting_date"], 1680770759);
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Voting_name"], "Voting 126");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Voting_type"], 0);
}

TEST_F(rpc, get_tx_with_parse_metadata_from_add_vote) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_tx = dynamic_cast<const t_mediator_command_request_get_tx&>(request);
					response = std::make_unique<t_mediator_command_response_get_tx>();
					auto & response_get_tx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
					const std::string tx_allmetadata_str = "5649a3d3c9a3d141917737b686a99a25007ae061ca4297da67c9b16e2bfe3241c849";
					std::vector<unsigned char> allmetadata;
					allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					int ret = 1;
					ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_allmetadata = allmetadata;
					const std::string tx_txid_str = "e6fe69ad60e33c89440bb5cefe21688dabb3e56508b40dede46fef3d14fdc271";
					t_hash_type txid;
					if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_txid = txid;
					EXPECT_EQ(request_get_tx.m_txid, txid);
					response_get_tx.m_transaction.m_type = t_transactiontype::add_secret_vote;
					const std::string tx_vin_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
					t_public_key_type pk;
					if(tx_vin_pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.resize(1);
					response_get_tx.m_transaction.m_vin.at(0).m_pk = pk;
					const std::string tx_vin_sign_str = "206553b31b4d951fbbec55a0b4f402848712fdbb5459fd1884091c9d33442c7e81a2a22e832644ed5c3809a0ba4e804c85c4afe5b8e025799c28c471f2c8be01";
					t_signature_type sign;
					if(tx_vin_sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(sign.data(), sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_sign = sign;
					const std::string tx_vin_txid_str = "008c9466adb69cdda0c7f2e5f790b021956912aa478838c745ca187cd1613b8e";
					t_hash_type vin_txid;
					if(tx_vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_txid = vin_txid;
					response_get_tx.m_transaction.m_vout.resize(1);
					response_get_tx.m_transaction.m_vout.at(0).m_amount = 1;
					const std::string tx_vout_pkh_str = "5cf5df8b1016c326323cc2a144de1e5ffea9bcd6c9ecd84def821e110228905e";
					t_hash_type pkh;
					if(tx_vout_pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size from tx");
					ret = sodium_hex2bin(pkh.data(), pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vout.at(0).m_pkh = pkh;
					assert(response != nullptr);
					return response;
	});
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_tx_with_parse_metadata";
	cmd["params"]["txid"] = "e6fe69ad60e33c89440bb5cefe21688dabb3e56508b40dede46fef3d14fdc271";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["transaction"]["allmetadata"], "5649a3d3c9a3d141917737b686a99a25007ae061ca4297da67c9b16e2bfe3241c849");
	EXPECT_EQ(result["result"]["data"]["transaction"]["txid"], "e6fe69ad60e33c89440bb5cefe21688dabb3e56508b40dede46fef3d14fdc271");
	EXPECT_EQ(result["result"]["data"]["transaction"]["type"], 0);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["pk"], "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["sign"], "206553b31b4d951fbbec55a0b4f402848712fdbb5459fd1884091c9d33442c7e81a2a22e832644ed5c3809a0ba4e804c85c4afe5b8e025799c28c471f2c8be01");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["vin_txid"], "008c9466adb69cdda0c7f2e5f790b021956912aa478838c745ca187cd1613b8e");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["amount"], 1);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["pkh"], "5cf5df8b1016c326323cc2a144de1e5ffea9bcd6c9ecd84def821e110228905e");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Voting_id"], "a3d3c9a3d141917737b686a99a25007ae061ca4297da67c9b16e2bfe3241c849");
}

TEST_F(rpc, get_tx_with_parse_metadata_from_organizer_auth_organizer) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_tx = dynamic_cast<const t_mediator_command_request_get_tx&>(request);
					response = std::make_unique<t_mediator_command_response_get_tx>();
					auto & response_get_tx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
					const std::string tx_allmetadata_str = "434ffec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc244350b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015";
					std::vector<unsigned char> allmetadata;
					allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					int ret = 1;
					ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_allmetadata = allmetadata;
					const std::string tx_txid_str = "e6fe69ad60e33c89440bb5cefe21688dabb3e56508b40dede46fef3d14fdc271";
					t_hash_type txid;
					if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_txid = txid;
					EXPECT_EQ(request_get_tx.m_txid, txid);
					response_get_tx.m_transaction.m_type = t_transactiontype::authorize_organizer;
					const std::string tx_vin_pk_str = "b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015";
					t_public_key_type pk;
					if(tx_vin_pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.resize(1);
					response_get_tx.m_transaction.m_vin.at(0).m_pk = pk;
					const std::string tx_vin_sign_str = "206553b31b4d951fbbec55a0b4f402848712fdbb5459fd1884091c9d33442c7e81a2a22e832644ed5c3809a0ba4e804c85c4afe5b8e025799c28c471f2c8be01";
					t_signature_type sign;
					if(tx_vin_sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(sign.data(), sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_sign = sign;
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					t_hash_type vin_txid;
					if(tx_vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_txid = vin_txid;
					response_get_tx.m_transaction.m_vout.resize(1);
					response_get_tx.m_transaction.m_vout.at(0).m_amount = 0;
					const std::string tx_vout_pkh_str = "5acf6f1a8a6b483c45b36a1d4d4eb8a18c30311ef0e2d6789c4ac08c6ff92be7";
					t_hash_type pkh;
					if(tx_vout_pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size from tx");
					ret = sodium_hex2bin(pkh.data(), pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vout.at(0).m_pkh = pkh;
					assert(response != nullptr);
					return response;
	});
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_tx_with_parse_metadata";
	cmd["params"]["txid"] = "e6fe69ad60e33c89440bb5cefe21688dabb3e56508b40dede46fef3d14fdc271";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["transaction"]["allmetadata"], "434ffec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc244350b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015");
	EXPECT_EQ(result["result"]["data"]["transaction"]["txid"], "e6fe69ad60e33c89440bb5cefe21688dabb3e56508b40dede46fef3d14fdc271");
	EXPECT_EQ(result["result"]["data"]["transaction"]["type"], 4);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["pk"], "b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["sign"], "206553b31b4d951fbbec55a0b4f402848712fdbb5459fd1884091c9d33442c7e81a2a22e832644ed5c3809a0ba4e804c85c4afe5b8e025799c28c471f2c8be01");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["amount"], 0);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["pkh"], "5acf6f1a8a6b483c45b36a1d4d4eb8a18c30311ef0e2d6789c4ac08c6ff92be7");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Voting_group/Organizer_pk"], "fec4f428b793daa87da536b40a1a8eadbe53e9c5e9a814a6f7e9c8945639fc24");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Organizer_parent_pk"], "b8af4d87cb1a37c32bbd224bd1947863f9766653a19cc2a81787989b8b143015");
}

TEST_F(rpc, get_tx_with_parse_metadata_from_add_personal_metadata) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					const auto request_get_tx = dynamic_cast<const t_mediator_command_request_get_tx&>(request);
					response = std::make_unique<t_mediator_command_response_get_tx>();
					auto & response_get_tx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
					const std::string tx_allmetadata_str = "5044077426406737d142630990992df79bd856a7709c378592cd8f76a795c1fccf1d";
					std::vector<unsigned char> allmetadata;
					allmetadata.resize(tx_allmetadata_str.size()/2);
					if(tx_allmetadata_str.size()!=allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size from tx");
					int ret = 1;
					ret = sodium_hex2bin(allmetadata.data(), allmetadata.size(),
										tx_allmetadata_str.data(), tx_allmetadata_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_allmetadata = allmetadata;
					const std::string tx_txid_str = "ef99e1a8477216e858a2ce4f8489d7e1fbbfe5379246f2c7a03bd523dd1e16f0";
					t_hash_type txid;
					if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size from tx");
					ret = sodium_hex2bin(txid.data(), txid.size(),
										tx_txid_str.data(), tx_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_txid = txid;
					EXPECT_EQ(request_get_tx.m_txid, txid);
					response_get_tx.m_transaction.m_type = t_transactiontype::hash_personal_data;
					const std::string tx_vin_pk_str = "530aa8149815decb979d5e11793bef932d340d5be81a1b7b11e383bbc6aa9f4b";
					t_public_key_type pk;
					if(tx_vin_pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size from tx");
					ret = sodium_hex2bin(pk.data(), pk.size(),
										tx_vin_pk_str.data(), tx_vin_pk_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.resize(1);
					response_get_tx.m_transaction.m_vin.at(0).m_pk = pk;
					const std::string tx_vin_sign_str = "3341a07f96517eac8a2d6291ed5c66f05e18f4dd729ba4bf35b02691ce234be32af02ff64249377d31c02bd336a7a5e60cb18848b0fddbe566779891e4041400";
					t_signature_type sign;
					if(tx_vin_sign_str.size()!=sign.size()*2) throw std::invalid_argument("Bad sign size from tx");
					ret = sodium_hex2bin(sign.data(), sign.size(),
										tx_vin_sign_str.data(), tx_vin_sign_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_sign = sign;
					const std::string tx_vin_txid_str = "0000000000000000000000000000000000000000000000000000000000000000";
					t_hash_type vin_txid;
					if(tx_vin_txid_str.size()!=vin_txid.size()*2) throw std::invalid_argument("Bad vin_txid size from tx");
					ret = sodium_hex2bin(vin_txid.data(), vin_txid.size(),
										tx_vin_txid_str.data(), tx_vin_txid_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vin.at(0).m_txid = vin_txid;
					response_get_tx.m_transaction.m_vout.resize(1);
					response_get_tx.m_transaction.m_vout.at(0).m_amount = 0;
					const std::string tx_vout_pkh_str = "5acf6f1a8a6b483c45b36a1d4d4eb8a18c30311ef0e2d6789c4ac08c6ff92be7";
					t_hash_type pkh;
					if(tx_vout_pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size from tx");
					ret = sodium_hex2bin(pkh.data(), pkh.size(),
										tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
										nullptr, nullptr, nullptr);
					if (ret!=0) throw std::runtime_error("hex2bin error");
					response_get_tx.m_transaction.m_vout.at(0).m_pkh = pkh;
					assert(response != nullptr);
					return response;
	});
	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_tx_with_parse_metadata";
	cmd["params"]["txid"] = "ef99e1a8477216e858a2ce4f8489d7e1fbbfe5379246f2c7a03bd523dd1e16f0";
	const auto result = rpc_exec->execute(cmd);
	EXPECT_EQ(result["result"]["status"], "done");
	EXPECT_EQ(result["result"]["data"]["transaction"]["allmetadata"], "5044077426406737d142630990992df79bd856a7709c378592cd8f76a795c1fccf1d");
	EXPECT_EQ(result["result"]["data"]["transaction"]["txid"], "ef99e1a8477216e858a2ce4f8489d7e1fbbfe5379246f2c7a03bd523dd1e16f0");
	EXPECT_EQ(result["result"]["data"]["transaction"]["type"], 10);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["pk"], "530aa8149815decb979d5e11793bef932d340d5be81a1b7b11e383bbc6aa9f4b");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["sign"], "3341a07f96517eac8a2d6291ed5c66f05e18f4dd729ba4bf35b02691ce234be32af02ff64249377d31c02bd336a7a5e60cb18848b0fddbe566779891e4041400");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vin"].at(0)["vin_txid"], "0000000000000000000000000000000000000000000000000000000000000000");
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["amount"], 0);
	EXPECT_EQ(result["result"]["data"]["transaction"]["vout"].at(0)["pkh"], "5acf6f1a8a6b483c45b36a1d4d4eb8a18c30311ef0e2d6789c4ac08c6ff92be7");
	EXPECT_EQ(result["result"]["data"]["parsed_metadata"]["Hash_of_personal_data"], "077426406737d142630990992df79bd856a7709c378592cd8f76a795c1fccf1d");
}

TEST_F(rpc, get_voting_by_id_waiting) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_voting_by_id = dynamic_cast<const t_mediator_command_request_get_voting_by_id&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_voting_by_id>();
					auto & response_get_voting_by_id = dynamic_cast<t_mediator_command_response_get_voting_by_id&>(*response);
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679183050;
						const uint32_t voting_end_time = 1679189050;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						voting_metadata.m_authorization_level = 1;
						voting_metadata.m_question = "Do you prefer option a or b?";
						t_hash_type voting_id;
						const std::string voting_id_str = "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						EXPECT_EQ(request_get_voting_by_id.m_voting_id, voting_id);
						response_get_voting_by_id.m_voting_metadata = voting_metadata;
						response_get_voting_by_id.m_voter_turnout = 0.0;
						response_get_voting_by_id.m_voting_status = 'W';
						response_get_voting_by_id.m_voting_results.emplace("option A", 0);
						response_get_voting_by_id.m_voting_results.emplace("option B", 0);
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_voting_by_id";
	cmd["params"]["voting_id"] = "fef8f1648639c18d5f37039f6fe350f8a6e86ea1092229f152f52bdc82258dc4";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["end_time"], 1679189050);
		EXPECT_EQ(result["result"]["data"]["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"]["start_time"], 1679183050);
		EXPECT_EQ(result["result"]["data"]["authorization_level"], 1);
		EXPECT_EQ(result["result"]["data"]["voting_question"], "Do you prefer option a or b?");
		EXPECT_EQ(result["result"]["data"]["votings_result"]["option A"], 0);
		EXPECT_EQ(result["result"]["data"]["votings_result"]["option B"], 0);
		EXPECT_EQ(result["result"]["data"]["status"], "waiting");
		EXPECT_EQ(result["result"]["data"]["type"], 0);
		EXPECT_EQ(result["result"]["data"]["voter_turnout"], 0.0);
	}
}

TEST_F(rpc, get_voting_by_id_active) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_voting_by_id = dynamic_cast<const t_mediator_command_request_get_voting_by_id&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_voting_by_id>();
					auto & response_get_voting_by_id = dynamic_cast<t_mediator_command_response_get_voting_by_id&>(*response);
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679079730;
						const uint32_t voting_end_time = 1679183030;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						voting_metadata.m_authorization_level = 1;
						voting_metadata.m_question = "Do you prefer option a or b?";
						t_hash_type voting_id;
						const std::string voting_id_str = "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						EXPECT_EQ(request_get_voting_by_id.m_voting_id, voting_id);
						response_get_voting_by_id.m_voting_metadata = voting_metadata;
						response_get_voting_by_id.m_voter_turnout = 57.0;
						response_get_voting_by_id.m_voting_status = 'V';
						response_get_voting_by_id.m_voting_results.emplace("option A", 27);
						response_get_voting_by_id.m_voting_results.emplace("option B", 30);
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_voting_by_id";
	cmd["params"]["voting_id"] = "feda4bc78f107badb2a0800e6471b753704707d2a9056e5941387a0657eb08a3";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["end_time"], 1679183030);
		EXPECT_EQ(result["result"]["data"]["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"]["start_time"], 1679079730);
		EXPECT_EQ(result["result"]["data"]["authorization_level"], 1);
		EXPECT_EQ(result["result"]["data"]["voting_question"], "Do you prefer option a or b?");
		EXPECT_EQ(result["result"]["data"]["votings_result"]["option A"], 27);
		EXPECT_EQ(result["result"]["data"]["votings_result"]["option B"], 30);
		EXPECT_EQ(result["result"]["data"]["status"], "active");
		EXPECT_EQ(result["result"]["data"]["type"], 0);
		EXPECT_EQ(result["result"]["data"]["voter_turnout"], 57.0);
	}
}

TEST_F(rpc, get_voting_by_id_finished) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .Times(AnyNumber())
	        .WillRepeatedly(
	            [](const t_mediator_command_request & request){
					const auto request_get_voting_by_id = dynamic_cast<const t_mediator_command_request_get_voting_by_id&>(request);
					std::unique_ptr<t_mediator_command_response> response;
					response = std::make_unique<t_mediator_command_response_get_voting_by_id>();
					auto & response_get_voting_by_id = dynamic_cast<t_mediator_command_response_get_voting_by_id&>(*response);
					{
						t_voting_metadata voting_metadata;
						voting_metadata.m_start_timepoint = 1679078630;
						const uint32_t voting_end_time = 1679083130;
						const uint32_t voting_time = voting_end_time - voting_metadata.m_start_timepoint;
						const uint32_t number_of_blocks = voting_time / n_blockchainparams::blocks_diff_time_in_sec;
						voting_metadata.m_number_of_blocks_to_the_end = number_of_blocks;
						voting_metadata.m_name = "Voting B";
						voting_metadata.m_voting_type = 0;
						voting_metadata.m_authorization_level = 1;
						voting_metadata.m_question = "Do you prefer option a or b?";
						t_hash_type voting_id;
						const std::string voting_id_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
						if(voting_id_str.size()!=voting_id.size()*2) throw std::invalid_argument("Bad voting_id size");
						const auto ret = sodium_hex2bin(voting_id.data(), voting_id.size(),
														voting_id_str.data(), voting_id_str.size(),
														nullptr, nullptr, nullptr);
						if (ret!=0) throw std::runtime_error("hex2bin error");
						EXPECT_EQ(request_get_voting_by_id.m_voting_id, voting_id);
						response_get_voting_by_id.m_voting_metadata = voting_metadata;
						response_get_voting_by_id.m_voter_turnout = 100.0;
						response_get_voting_by_id.m_voting_status = 'X';
						response_get_voting_by_id.m_voting_results.emplace("option A", 57);
						response_get_voting_by_id.m_voting_results.emplace("option B", 43);
					}
					assert(response != nullptr);
					return response;
	});

	auto rpc_exec = std::make_shared<c_rpc_exec>();
	rpc_exec->install_rpc_handlers();	
	std::unique_ptr<c_rpc_server_base> rpc_server_test = std::make_unique<c_rpc_server_test>(rpc_exec);
	c_rpc_module rpc_module(std::move(rpc_server_test), m_mediator_mock);
	rpc_exec->set_rpc_module(rpc_module);

	nlohmann::json cmd;
	cmd["id"] = 1;
	cmd["jsonrpc"] = 2.0;
	cmd["method"] = "get_voting_by_id";
	cmd["params"]["voting_id"] = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	const auto result = rpc_exec->execute(cmd);
	{
		EXPECT_EQ(result["result"]["status"], "done");
		EXPECT_EQ(result["result"]["data"]["end_time"], 1679083130);
		EXPECT_EQ(result["result"]["data"]["name"], "Voting B");
		EXPECT_EQ(result["result"]["data"]["start_time"], 1679078630);
		EXPECT_EQ(result["result"]["data"]["authorization_level"], 1);
		EXPECT_EQ(result["result"]["data"]["voting_question"], "Do you prefer option a or b?");
		EXPECT_EQ(result["result"]["data"]["votings_result"]["option A"], 57);
		EXPECT_EQ(result["result"]["data"]["votings_result"]["option B"], 43);
		EXPECT_EQ(result["result"]["data"]["status"], "finished");
		EXPECT_EQ(result["result"]["data"]["type"], 0);
		EXPECT_EQ(result["result"]["data"]["voter_turnout"], 100.0);
	}
}
