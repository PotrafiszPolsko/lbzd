#include <gtest/gtest.h>
#include <queue>
#include "../src/blockchain_module.hpp"
#include "../src/blockchain_module_builder.hpp"
#include "mediator_mock.hpp"
#include "../src/adminsys.hpp"
#include "../src/serialization_utils.hpp"
#include "blockchain_mock.hpp"
#include "utxo_mock.hpp"
#include "../src/txid_generate.hpp"

class blockchain_module_test : public ::testing::Test {
	protected:
		blockchain_module_test();
		void SetUp() override;
		void TearDown() override;
		c_mediator_mock m_mediator_mock;
		const std::filesystem::path m_datadir_path = "./ivoting-test";
		std::vector<std::unique_ptr<c_blockchain_module>> m_blockchain_modules;
		t_root_keypair m_adminsys_keypair;
		virtual boost::program_options::variables_map generate_variable_map(const std::filesystem::path & path) const;
		t_root_keypair generate_keypair() const;
		std::unique_ptr<c_blockchain_module> generate_blockchain_module();
		void sign_block(c_block & block, const t_root_keypair & keypair);
		t_root_keypair generate_adminsys_keypair() const;
		const std::filesystem::path get_next_datadir_path();
};

t_root_keypair blockchain_module_test::generate_keypair() const{
	n_bip32::c_key_manager_BIP32 key_manager;
	const auto miner_keypair = key_manager.get_root_key();
	return miner_keypair;
}

const std::filesystem::path blockchain_module_test::get_next_datadir_path() {
	static std::filesystem::path::value_type module_number = '0';
	const auto module_number_as_str = std::filesystem::path::string_type(1, module_number);
	const std::filesystem::path datadir_path = m_datadir_path / std::filesystem::path(module_number_as_str);
	module_number++;
	return datadir_path;
}

std::unique_ptr<c_blockchain_module> blockchain_module_test::generate_blockchain_module() {
	const std::filesystem::path datadir_path = get_next_datadir_path();
	c_blockchain_module_builder blockchain_module_builder;
	const auto variable_map = generate_variable_map(datadir_path);
	blockchain_module_builder.set_program_options(variable_map);
	return blockchain_module_builder.get_result(m_mediator_mock);
}

void blockchain_module_test::sign_block(c_block & block, const t_root_keypair & keypair) {
	const auto & block_hash = block.m_header.m_actual_hash;
	const auto block_signature = n_bip32::c_key_manager_BIP32::sign_root(block_hash.data(), block_hash.size(), keypair);
	block.m_header.m_all_signatures.push_back(block_signature);
}

t_root_keypair blockchain_module_test::generate_adminsys_keypair() const {
	n_bip32::c_key_manager_BIP32 key_manager(n_blockchainparams::entropy_seed);
	return key_manager.get_root_key();
}

blockchain_module_test::blockchain_module_test()
	:
	  m_adminsys_keypair(generate_adminsys_keypair())
{}

void blockchain_module_test::SetUp() {
	using testing::_;
	
	const size_t number_of_blockchain_modules = 10;
	for (size_t i = 0; i < number_of_blockchain_modules; i++)
		m_blockchain_modules.emplace_back(generate_blockchain_module());
}

void blockchain_module_test::TearDown() {
	for (auto & blockchain_module : m_blockchain_modules)
		blockchain_module->stop();
	std::filesystem::remove_all(m_datadir_path);
}

boost::program_options::variables_map blockchain_module_test::generate_variable_map(const std::filesystem::path & path) const {
	boost::program_options::variables_map variable_map;
	variable_map.insert(std::make_pair("par", boost::program_options::variable_value(static_cast<unsigned short>(1), false)));
	variable_map.insert(std::make_pair("datadir", boost::program_options::variable_value(path, false)));
	variable_map.insert(std::make_pair("force-mine", boost::program_options::variable_value(false, false)));
	boost::program_options::notify(variable_map);
	return variable_map;
}

TEST_F(blockchain_module_test, genesis_block) {
	c_adminsys adminsys(m_datadir_path);
	auto genesis_block = adminsys.mine_genesis_block();
	sign_block(genesis_block, m_adminsys_keypair);
	auto & blockchain_module = m_blockchain_modules.at(0);
	ASSERT_NO_THROW(blockchain_module->add_new_block(genesis_block));
	const auto block_from_bc = blockchain_module->get_block_at_height(0);
	EXPECT_EQ(genesis_block, block_from_bc);
	const auto last_block_hash = blockchain_module->get_last_block_hash();
	EXPECT_EQ(last_block_hash, genesis_block.m_header.m_actual_hash);
	t_hash_type zero_hash;
	zero_hash.fill(0x00);
	const auto headers = blockchain_module->get_headers_proto(zero_hash, zero_hash);
	ASSERT_EQ(headers.size(), 1);
	const auto first_header = header_from_protobuf(headers.at(0));
	EXPECT_EQ(first_header.m_actual_hash, last_block_hash);
}

////////////////////////////////////////////////////////////////////////////////

class blockchain_module_test_miner : public blockchain_module_test {
	protected:
		boost::program_options::variables_map generate_variable_map(const std::filesystem::path & path) const override;
		void SetUp() override;
		std::unique_ptr<c_blockchain_module> generate_blockchain_module(size_t index);
#ifdef COVERAGE_TESTS
		static constexpr size_t m_number_of_blockchain_modules = 1;
#elif IVOTING_TESTS
		static constexpr size_t m_number_of_blockchain_modules = 10;
#endif
		std::vector<t_root_keypair> m_miner_keypairs;
		std::array<c_mediator_mock, m_number_of_blockchain_modules> m_mediator_mocks;
};

boost::program_options::variables_map blockchain_module_test_miner::generate_variable_map(const std::filesystem::path & path) const {
	auto variable_map = blockchain_module_test::generate_variable_map(path);
	variable_map.insert(std::make_pair("gen", boost::program_options::variable_value()));
	return variable_map;
}

void blockchain_module_test_miner::SetUp() {
	for (size_t i = 0; i < m_number_of_blockchain_modules; i++) {
		const auto miner_keypair = generate_keypair();
		m_miner_keypairs.emplace_back(miner_keypair);
		auto blockchain_module = generate_blockchain_module(i);
		m_blockchain_modules.emplace_back(std::move(blockchain_module));
	}
	c_adminsys adminsys(m_datadir_path);
	auto genesis_block = adminsys.mine_genesis_block();
	sign_block(genesis_block, m_adminsys_keypair);
	for (auto & blockchain_module : m_blockchain_modules)
		blockchain_module->add_new_block(genesis_block);
	c_blockchain adminsys_blockchain(m_datadir_path / "adminsys");
	adminsys_blockchain.add_block(genesis_block);
	c_mempool adminsys_mempool;
	c_utxo adminsys_utxo(m_datadir_path / "adminsys");
	for (const auto & miner_keypair : m_miner_keypairs) {
		auto miner_auth_tx = adminsys.generate_miner_auth_tx(miner_keypair.m_public_key);
		adminsys_mempool.add_transaction(std::move(miner_auth_tx), adminsys_utxo);
	}
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec));
	auto block = adminsys.mine_block(genesis_block, adminsys_mempool);
	sign_block(block, m_adminsys_keypair);
	for (auto & blockchain_module : m_blockchain_modules)
	  blockchain_module->add_new_block(block);
}

std::unique_ptr<c_blockchain_module> blockchain_module_test_miner::generate_blockchain_module(size_t index) {
  const std::filesystem::path datadir_path = get_next_datadir_path();
  c_blockchain_module_builder blockchain_module_builder;
  const auto variable_map = generate_variable_map(datadir_path);
  blockchain_module_builder.set_program_options(variable_map);
  return blockchain_module_builder.get_result(m_mediator_mocks.at(index));
}

TEST_F(blockchain_module_test_miner, multi_miner) {
	using testing::_;
	using testing::AnyNumber;
	std::queue<c_block> broadcasted_blocks;
	std::mutex broadcasted_blocks_mtx;
	std::atomic<bool> broadcast_block_stop_flag = false;
	for (size_t i = 0; i < m_number_of_blockchain_modules; i++) {
		EXPECT_CALL(m_mediator_mocks.at(i), notify(_))
				.Times(AnyNumber())
				.WillRepeatedly(
					[&, i](const t_mediator_command_request & request){
						std::unique_ptr<t_mediator_command_response> response;
						switch (request.m_type) {
							case t_mediator_cmd_type::e_broadcast_block:
							{
								const auto & broadcast_block_request = dynamic_cast<const t_mediator_command_request_broadcast_block&>(request);
								response = std::make_unique<t_mediator_command_response_broadcast_block>();
								const auto & block = broadcast_block_request.m_block;
								std::lock_guard<std::mutex> lock(broadcasted_blocks_mtx);
									broadcasted_blocks.push(block);
								break;
							}
							case t_mediator_cmd_type::e_get_pk_and_sign:
							{
								const auto & sign_message_request = dynamic_cast<const t_mediator_command_request_get_pk_and_sign&>(request);
								response = std::make_unique<t_mediator_command_response_get_pk_and_sign>();
								auto & response_get_pk_and_sign = dynamic_cast<t_mediator_command_response_get_pk_and_sign&>(*response);
								const auto & root_keypair = m_miner_keypairs.at(i);
								response_get_pk_and_sign.m_pk = root_keypair.m_public_key;
								const auto & data_to_sign = sign_message_request.m_msg_to_sign;
								response_get_pk_and_sign.m_sign = 
										n_bip32::c_key_manager_BIP32::sign_root(reinterpret_cast<const unsigned char *>(data_to_sign.data()), data_to_sign.size(), root_keypair);
								break;
							}
							case t_mediator_cmd_type::e_get_pk:
							{
								const auto & root_keypair = m_miner_keypairs.at(i);
								const auto pk = root_keypair.m_public_key;
								response = std::make_unique<t_mediator_command_response_get_pk>();
								auto & response_get_pk = dynamic_cast<t_mediator_command_response_get_pk&>(*response);
								response_get_pk.m_pk = pk;
								break;
							}
							case t_mediator_cmd_type::e_sign_message_by_main_identity:
							{
								const auto & request_sign = dynamic_cast<const t_mediator_command_request_sign_message_by_main_identity&>(request);
								const auto & data_to_sign = request_sign.m_msg;
								response = std::make_unique<t_mediator_command_response_sign_message_by_main_identity>();
								auto & response_sign_message = dynamic_cast<t_mediator_command_response_sign_message_by_main_identity&>(*response);
								const auto & root_keypair = m_miner_keypairs.at(i);
								response_sign_message.m_sign = 
										n_bip32::c_key_manager_BIP32::sign_root(reinterpret_cast<const unsigned char *>(data_to_sign.data()), data_to_sign.size(), root_keypair);
								break;
							}
							default:
								assert(false);
								break;
						}
						assert(response != nullptr);
						return response;
						
				});
	}
	std::thread broadcast_block_thread([&](){
		while(!broadcast_block_stop_flag) {
			std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec));
			std::lock_guard<std::mutex> lock(broadcasted_blocks_mtx);
			if (broadcasted_blocks.empty()) continue;
			const auto & block = broadcasted_blocks.front();
			for (auto & blockchain_module : m_blockchain_modules) blockchain_module->add_new_block(block);
			broadcasted_blocks.pop();
		}
	});
#ifdef COVERAGE_TESTS
	  const size_t number_how_many_times_more = 1;
#elif IVOTING_TESTS
	  const size_t number_how_many_times_more = 12;
#endif
	for (auto & blockchain_module : m_blockchain_modules) blockchain_module->run();
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec * number_how_many_times_more));
	broadcast_block_stop_flag = true;
	TearDown();
	if (broadcast_block_thread.joinable()) broadcast_block_thread.join();
}

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

TEST(blockchain_module, get_auth_txid) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_public_key_type pk;
	const std::string pk_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = sodium_hex2bin(pk.data(), pk.size(),
							pk_str.data(), pk_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type txid;
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	using ::testing::Return;
	EXPECT_CALL(ut, get_auth_txid(pk))
	        .WillOnce(Return(txid));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto txid_test = bc_module->get_auth_txid(pk);
	EXPECT_EQ(txid_test, txid);
}

TEST(blockchain_module, get_hashes_of_voting_protocols) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_hash_type hash_protocol_1;
	const std::string hash_protocol_1_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(hash_protocol_1_str.size()!=hash_protocol_1.size()*2) throw std::invalid_argument("Bad hash_protocol size");
	int ret = sodium_hex2bin(hash_protocol_1.data(), hash_protocol_1.size(),
							hash_protocol_1_str.data(), hash_protocol_1_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type hash_protocol_2;
	const std::string hash_protocol_2_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(hash_protocol_2_str.size()!=hash_protocol_2.size()*2) throw std::invalid_argument("Bad hash_protocol size");
	ret = sodium_hex2bin(hash_protocol_2.data(), hash_protocol_2.size(),
						hash_protocol_2_str.data(), hash_protocol_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<t_hash_type> hashes_protocol;
	hashes_protocol.push_back(hash_protocol_1);
	hashes_protocol.push_back(hash_protocol_2);
	
	using ::testing::Return;
	EXPECT_CALL(ut, get_hashes_of_voting_protocols())
	        .WillOnce(Return(hashes_protocol));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto hashes_protocol_test = bc_module->get_hashes_voting_protocols();
	EXPECT_EQ(hashes_protocol_test, hashes_protocol);
}

TEST(blockchain_module, get_voting_protocol_txid) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	c_blockchain_mock &bc = dynamic_cast<c_blockchain_mock&>(*blockchain);
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_hash_type hash_protocol;
	const std::string hash_protocol_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(hash_protocol_str.size()!=hash_protocol.size()*2) throw std::invalid_argument("Bad hash_protocol size");
	int ret = sodium_hex2bin(hash_protocol.data(), hash_protocol.size(),
							hash_protocol_str.data(), hash_protocol_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	c_transaction tx;
	t_hash_type txid;
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_txid = txid;
	tx.m_vin.resize(1);
	tx.m_vout.resize(1);
	const std::string tx_allmetadata_str = "dd4f8524a28dd9d80e70eb536372f08aa0a7a0eaf982fc7ca8910affc42ca10c56ea";
	tx.m_allmetadata.resize(tx_allmetadata_str.size()/2);
	if(tx_allmetadata_str.size()!=tx.m_allmetadata.size()*2) throw std::invalid_argument("Bad allmetadata size");
	ret = sodium_hex2bin(tx.m_allmetadata.data(), tx.m_allmetadata.size(),
						tx_allmetadata_str.data(), tx_allmetadata_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_type = t_transactiontype::another_voting_protocol;
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
	const std::string tx_vout_pkh_str = "0000000000000000000000000000000000000000000000000000000000000000";
	if(tx_vout_pkh_str.size()!=tx.m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(tx.m_vout.at(0).m_pkh.data(), tx.m_vout.at(0).m_pkh.size(),
						tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	using ::testing::Return;
	EXPECT_CALL(ut, get_voting_protocol_txid(hash_protocol))
	        .WillOnce(Return(txid));
	EXPECT_CALL(bc, get_transaction(txid))
	        .WillOnce(Return(tx));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto tx_test = bc_module->get_tx_voting_protocol(hash_protocol);
	EXPECT_EQ(tx_test, tx);
}

TEST(blockchain_module, is_pk_miner) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_public_key_type pk;
	const std::string pk_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = sodium_hex2bin(pk.data(), pk.size(),
							pk_str.data(), pk_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const bool is_pk_miner = true;

	using ::testing::Return;
	EXPECT_CALL(ut, is_pk_miner(pk))
	        .WillOnce(Return(is_pk_miner));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto is_pk_miner_test = bc_module->is_pk_miner(pk);
	EXPECT_EQ(is_pk_miner_test, is_pk_miner);
}

TEST(blockchain_module, is_pk_organizer) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();
	c_utxo_mock &ut = dynamic_cast<c_utxo_mock&>(*utxo);

	t_public_key_type pk;
	const std::string pk_str = "dda3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(pk_str.size()!=pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = sodium_hex2bin(pk.data(), pk.size(),
							pk_str.data(), pk_str.size(),
							nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	const bool is_pk_organizer = false;

	using ::testing::Return;
	EXPECT_CALL(ut, is_pk_organizer(pk))
	        .WillOnce(Return(is_pk_organizer));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto is_pk_organizer_test = bc_module->is_pk_organizer(pk);
	EXPECT_EQ(is_pk_organizer_test, is_pk_organizer);
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

TEST(blockchain_module, authorize_miner_by_adminsys) {
	std::unique_ptr<c_blockchain> blockchain = std::make_unique<c_blockchain_mock>();
	std::unique_ptr<c_utxo> utxo = std::make_unique<c_utxo_mock>();

	t_public_key_type miner_pk;
	const std::string miner_pk_str = "c2ac71261b939b4c785d0c64a33743cc6475e7eb45cfdbca2e0ac8a9d0b3760c";
	if(miner_pk_str.size()!=miner_pk.size()*2) throw std::invalid_argument("Bad pk size");
	int ret = 1;
	ret = sodium_hex2bin(miner_pk.data(), miner_pk.size(),
						miner_pk_str.data(), miner_pk_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_signature_type signature;
	const std::string signature_str = "439a6c99a9ca67487e8f2840fb716d7d72bb2d86f533c218c975e6a5526c795523801da2c9a3b272fc4ad11c3f600ed75594e60c4cd0ab02196de90f62faf00f";
	if(signature_str.size()!=signature.size()*2) throw std::invalid_argument("Bad signature size");
	ret = sodium_hex2bin(signature.data(), signature.size(),
						signature_str.data(), signature_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	c_mediator_mock mediator_mock;
	using ::testing::_;
	using ::testing::AnyNumber;
	EXPECT_CALL(mediator_mock, notify(_))
			.Times(AnyNumber())
			.WillRepeatedly(
				[&](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					switch (request.m_type) {
						case t_mediator_cmd_type::e_get_pk:
						{
							response = std::make_unique<t_mediator_command_response_get_pk>();
							auto & response_get_pk = dynamic_cast<t_mediator_command_response_get_pk&>(*response);
							response_get_pk.m_pk = n_blockchainparams::admins_sys_pub_keys.at(0);
							break;
						}
						case t_mediator_cmd_type::e_sign_message_by_main_identity:
						{
							response = std::make_unique<t_mediator_command_response_sign_message_by_main_identity>();
							auto & response_sign_message = dynamic_cast<t_mediator_command_response_sign_message_by_main_identity&>(*response);
							response_sign_message.m_sign = signature;
							break;
						}
						default:
							assert(false);
							break;
					}
					assert(response != nullptr);
					return response;
					
			});

	c_transaction tx;
	tx.m_type = t_transactiontype::authorize_miner;
	{
		c_vout vout;
		vout.m_pkh = generate_hash(miner_pk);
		tx.m_vout.push_back(std::move(vout));
	}
	{
		c_vin vin;
		vin.m_txid.fill(0x00);
		vin.m_pk = n_blockchainparams::admins_sys_pub_keys.at(0);
		vin.m_sign.fill(0x00);
		tx.m_vin.push_back(std::move(vin));
	}
	std::copy(miner_pk.cbegin(), miner_pk.cend(), std::back_inserter(tx.m_allmetadata));
	
	tx.m_txid = c_txid_generate::generate_txid(tx);
	tx.m_vin.at(0).m_sign = signature;

	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	const auto tx_test = bc_module->authorize_miner_by_adminsys(miner_pk, n_blockchainparams::admins_sys_pub_keys.at(0));
	EXPECT_EQ(tx, tx_test);
}

TEST(blockchain_module, is_block_exists_true) {
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
	tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
	nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc, block_exists(actual_hash))
	        .WillOnce(Return(true));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	EXPECT_TRUE(bc_module->block_exists(actual_hash));
}

TEST(blockchain_module, is_block_exists_false) {
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
	tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
	nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc, block_exists(actual_hash))
	        .WillOnce(Return(false));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	EXPECT_FALSE(bc_module->block_exists(actual_hash));
}

TEST(blockchain_module, is_blockchain_synchronized_false) {
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
	tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
	nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc, get_last_block())
	        .WillOnce(Return(block));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	EXPECT_FALSE(bc_module->is_blockchain_synchronized());
}

TEST(blockchain_module, is_blockchain_synchronized_true) {
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
	block.m_header.m_block_time = static_cast<uint32_t>(get_unix_time());
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
	const std::string tx_vout_pkh_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(tx_vout_pkh_str.size()!=txs.at(0).m_vout.at(0).m_pkh.size()*2) throw std::invalid_argument("Bad vout pkh size");
	ret = sodium_hex2bin(txs.at(0).m_vout.at(0).m_pkh.data(), txs.at(0).m_vout.at(0).m_pkh.size(),
	tx_vout_pkh_str.data(), tx_vout_pkh_str.size(),
	nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	block.m_transaction = txs;

	using ::testing::Return;
	EXPECT_CALL(bc, get_last_block())
	        .WillOnce(Return(block));

	c_mediator_mock mediator_mock;
	auto bc_module = std::make_unique<c_blockchain_module>(mediator_mock, std::move(blockchain), std::move(utxo));
	EXPECT_TRUE(bc_module->is_blockchain_synchronized());
}
