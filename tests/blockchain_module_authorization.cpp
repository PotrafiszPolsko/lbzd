#include <gtest/gtest.h>
#include "../src/blockchain_module_builder.hpp"
#include "../src/params.hpp"
#include "mediator_mock.hpp"
#include "../src/adminsys.hpp"
#include "../src/wallet.hpp"

class blockchain_module_authorization : public ::testing::Test {
	protected:
		blockchain_module_authorization();
		void SetUp() override;
		void TearDown() override;
		void setup_mediators();
		void setup_mediator(c_mediator_mock & mediator_mock, t_root_keypair keypair);
		boost::program_options::variables_map generate_variable_map(const std::filesystem::path & path) const;
		t_root_keypair generate_adminsys_keypair() const;
		void sign_block(c_block & block, const t_root_keypair & keypair);
		t_root_keypair m_adminsys_keypair;
		c_mediator_mock m_mediator_mock_adminsys;
		c_mediator_mock m_mediator_mock_organizer_A;
		c_mediator_mock m_mediator_mock_organizer_B;
		const std::filesystem::path m_datadir_path = "./ivoting-test";
		const std::filesystem::path m_wallet_path_adminsys = m_datadir_path / "adminsys_wallet";
		const std::filesystem::path m_wallet_path_organizer_A = m_datadir_path / "organizer_A_wallet";
		const std::filesystem::path m_wallet_path_organizer_B = m_datadir_path / "organizer_B_wallet";
		c_wallet m_organizer_A_wallet;
		c_wallet m_organizer_B_wallet;
		std::unique_ptr<c_blockchain_module> m_blockchain_module_adminsys;
		std::unique_ptr<c_blockchain_module> m_blockchain_module_organizer_A;
		std::unique_ptr<c_blockchain_module> m_blockchain_module_organizer_B;
};

blockchain_module_authorization::blockchain_module_authorization()
	:
	  m_adminsys_keypair(generate_adminsys_keypair()),
	  m_organizer_A_wallet(m_wallet_path_organizer_A),
	  m_organizer_B_wallet(m_wallet_path_organizer_B)
{
}

void blockchain_module_authorization::SetUp() {
	c_blockchain_module_builder blockchain_module_builder;
	{
		const auto variable_map = generate_variable_map(m_datadir_path/"adminsys");
		blockchain_module_builder.set_program_options(variable_map);
		m_blockchain_module_adminsys = blockchain_module_builder.get_result(m_mediator_mock_adminsys);
	}
	{
		const auto variable_map = generate_variable_map(m_datadir_path/"organizer_A");
		blockchain_module_builder.set_program_options(variable_map);
		m_blockchain_module_organizer_A = blockchain_module_builder.get_result(m_mediator_mock_organizer_A);
	}
	{
		const auto variable_map = generate_variable_map(m_datadir_path/"organizer_B");
		blockchain_module_builder.set_program_options(variable_map);
		m_blockchain_module_organizer_B = blockchain_module_builder.get_result(m_mediator_mock_organizer_B);
	}
	setup_mediators();
}

void blockchain_module_authorization::TearDown() {
	m_blockchain_module_adminsys->stop();
	std::filesystem::remove_all(m_datadir_path);
}

void blockchain_module_authorization::setup_mediators() {
	setup_mediator(m_mediator_mock_adminsys, m_adminsys_keypair);
	setup_mediator(m_mediator_mock_organizer_A, m_organizer_A_wallet.get_main_keypair());
	setup_mediator(m_mediator_mock_organizer_B, m_organizer_B_wallet.get_main_keypair());
}

void blockchain_module_authorization::setup_mediator(c_mediator_mock & mediator_mock, t_root_keypair keypair) {
	using testing::_;
	using testing::AnyNumber;
	EXPECT_CALL(mediator_mock, notify(_))
			.Times(AnyNumber())
			.WillRepeatedly(
				[this, keypair, &mediator_mock](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					switch (request.m_type) {
						case t_mediator_cmd_type::e_broadcast_block:
						{
							if (std::addressof(mediator_mock) == std::addressof(m_mediator_mock_adminsys)) {
								const auto & request_broadcast_mediator = dynamic_cast<const t_mediator_command_request_broadcast_block&>(request);
								m_blockchain_module_organizer_A->add_new_block(request_broadcast_mediator.m_block);
								m_blockchain_module_organizer_B->add_new_block(request_broadcast_mediator.m_block);
							}
							response = std::make_unique<t_mediator_command_response_broadcast_block>();
							break;
						}
						case t_mediator_cmd_type::e_get_pk_and_sign:
						{
							const auto & sign_message_request = dynamic_cast<const t_mediator_command_request_get_pk_and_sign&>(request);
							response = std::make_unique<t_mediator_command_response_get_pk_and_sign>();
							auto & response_get_pk_and_sign = dynamic_cast<t_mediator_command_response_get_pk_and_sign&>(*response);
							const auto & root_keypair = keypair;
							response_get_pk_and_sign.m_pk = root_keypair.m_public_key;
							const auto & data_to_sign = sign_message_request.m_msg_to_sign;
							response_get_pk_and_sign.m_sign = 
									n_bip32::c_key_manager_BIP32::sign_root(reinterpret_cast<const unsigned char *>(data_to_sign.data()), data_to_sign.size(), root_keypair);
							break;
						}
						case t_mediator_cmd_type::e_get_pk:
						{
							const auto pk = keypair.m_public_key;
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
							const auto & root_keypair = keypair;
							response_sign_message.m_sign = 
									n_bip32::c_key_manager_BIP32::sign_root(reinterpret_cast<const unsigned char *>(data_to_sign.data()), data_to_sign.size(), root_keypair);
							break;
						}
						default:
							break;
					}
					assert(response != nullptr);
					return response;
					
	});
}

boost::program_options::variables_map blockchain_module_authorization::generate_variable_map(const std::filesystem::path & path) const {
	boost::program_options::variables_map variable_map;
	variable_map.insert(std::make_pair("par", boost::program_options::variable_value(static_cast<unsigned short>(1), false)));
	variable_map.insert(std::make_pair("gen", boost::program_options::variable_value()));
	variable_map.insert(std::make_pair("datadir", boost::program_options::variable_value(path, false)));
	variable_map.insert(std::make_pair("force-mine", boost::program_options::variable_value(false, false)));
	boost::program_options::notify(variable_map);
	return variable_map;
}

t_root_keypair blockchain_module_authorization::generate_adminsys_keypair() const {
	n_bip32::c_key_manager_BIP32 key_manager(n_blockchainparams::entropy_seed);
	return key_manager.get_root_key();
}

void blockchain_module_authorization::sign_block(c_block & block, const t_root_keypair & keypair) {
	const auto & block_hash = block.m_header.m_actual_hash;
	const auto block_signature = n_bip32::c_key_manager_BIP32::sign_root(block_hash.data(), block_hash.size(), keypair);
	block.m_header.m_all_signatures.push_back(block_signature);
}

void test_transaction(const c_transaction & tx, const t_transactiontype & type, const c_transaction & tx_from_bc) {
	EXPECT_EQ(tx, tx_from_bc);
	EXPECT_EQ(type, tx_from_bc.m_type);
	EXPECT_EQ(tx.m_vin.size(), tx_from_bc.m_vin.size());
	for(size_t i=0; i<tx.m_vin.size(); i++) {
		EXPECT_EQ(tx.m_vin.at(i).m_txid, tx_from_bc.m_vin.at(i).m_txid);
		EXPECT_EQ(tx.m_vin.at(i).m_sign, tx_from_bc.m_vin.at(i).m_sign);
		EXPECT_EQ(tx.m_vin.at(i).m_pk, tx_from_bc.m_vin.at(i).m_pk);
	}
	EXPECT_EQ(tx.m_vout.size(), tx_from_bc.m_vout.size());
	for(size_t i=0; i<tx.m_vout.size(); i++) {
		EXPECT_EQ(tx.m_vout.at(i).m_pkh, tx_from_bc.m_vout.at(i).m_pkh);
	}
	EXPECT_EQ(tx.m_txid, tx_from_bc.m_txid);
	EXPECT_EQ(tx.m_allmetadata, tx_from_bc.m_allmetadata);
}

void test_is_organizer_auth(const c_blockchain_module & blockchain_module_adminsys, const t_public_key_type & organizer_pk, const t_hash_type & txid) {
	EXPECT_FALSE(n_blockchainparams::is_pk_adminsys(organizer_pk));
	EXPECT_TRUE(blockchain_module_adminsys.is_pk_organizer(organizer_pk));
	EXPECT_TRUE(blockchain_module_adminsys.is_transaction_in_blockchain(txid));
}

void test_add_tx_to_blockchain(c_blockchain_module & blockchain_module_adminsys, const c_transaction & tx) {
	EXPECT_TRUE(blockchain_module_adminsys.add_new_transaction(tx));
	EXPECT_EQ(blockchain_module_adminsys.get_number_of_mempool_transactions(), 1);
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)); // wait for next block
	EXPECT_EQ(blockchain_module_adminsys.get_number_of_mempool_transactions(), 0);
}

void test_actor_is_unauthorized(const c_blockchain_module & blockchain_module_adminsys, const t_public_key_type & actor_pk) {
	EXPECT_FALSE(n_blockchainparams::is_pk_adminsys(actor_pk));
	EXPECT_FALSE(blockchain_module_adminsys.is_pk_organizer(actor_pk));
}

TEST_F(blockchain_module_authorization, authorization) {
	m_blockchain_module_adminsys->run();
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)); // wait for next block
	const auto organizer_A_pk = m_organizer_A_wallet.get_main_pk();
	EXPECT_NO_THROW(m_blockchain_module_adminsys->authorize_organizer_by_adminsys(organizer_A_pk, m_adminsys_keypair.m_public_key));
	const auto organizer_A_auth_tx = m_blockchain_module_adminsys->authorize_organizer_by_adminsys(organizer_A_pk, m_adminsys_keypair.m_public_key);
	test_add_tx_to_blockchain(*m_blockchain_module_adminsys, organizer_A_auth_tx);
	test_is_organizer_auth(*m_blockchain_module_adminsys, organizer_A_pk, organizer_A_auth_tx.m_txid);
	EXPECT_THROW(m_blockchain_module_adminsys->authorize_organizer_by_adminsys(organizer_A_pk, m_adminsys_keypair.m_public_key), std::runtime_error);
	const auto organizer_A_auth_tx_from_bc = m_blockchain_module_adminsys->get_transaction(organizer_A_auth_tx.m_txid);
	test_transaction(organizer_A_auth_tx, t_transactiontype::authorize_organizer, organizer_A_auth_tx_from_bc);

	const auto organizer_B_pk = m_organizer_B_wallet.get_main_pk();
	EXPECT_NO_THROW(m_blockchain_module_adminsys->authorize_organizer_by_adminsys(organizer_B_pk, m_adminsys_keypair.m_public_key));
	const auto organizer_B_auth_tx = m_blockchain_module_adminsys->authorize_organizer_by_adminsys(organizer_B_pk, m_adminsys_keypair.m_public_key);
	test_add_tx_to_blockchain(*m_blockchain_module_adminsys, organizer_B_auth_tx);
	test_is_organizer_auth(*m_blockchain_module_adminsys, organizer_B_pk, organizer_A_auth_tx.m_txid);
	EXPECT_THROW(m_blockchain_module_adminsys->authorize_organizer_by_adminsys(organizer_B_pk, m_adminsys_keypair.m_public_key), std::runtime_error);
	const auto organizer_B_auth_tx_from_bc = m_blockchain_module_adminsys->get_transaction(organizer_B_auth_tx.m_txid);
	test_transaction(organizer_B_auth_tx, t_transactiontype::authorize_organizer, organizer_B_auth_tx_from_bc);
}

