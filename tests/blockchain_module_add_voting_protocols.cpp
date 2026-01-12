#include <gtest/gtest.h>
#include <random>
#include "../src/params.hpp"
#include "mediator_mock.hpp"
#include "../src/blockchain_module_builder.hpp"
#include "../src/serialization_utils.hpp"
#include "../src/merkle_tree.hpp"

class blockchain_module_add_voting_protocols : public ::testing::Test {
	protected:
		const size_t m_number_protocols;
		std::vector<std::string> m_voting_protocols;
		blockchain_module_add_voting_protocols();
		t_root_keypair generate_adminsys_keypair() const;
		void add_tx_of_add_vote(const std::string & option_str, const size_t counter_voter, const t_hash_type & voting_id);
		boost::program_options::variables_map generate_variable_map(const std::filesystem::path & path) const;
		void setup_mediators();
		void setup_mediator(c_mediator_mock & mediator_mock, t_root_keypair keypair);
		void SetUp() override;
		void TearDown() override;
		t_root_keypair m_adminsys_keypair;
		c_mediator_mock m_mediator_mock_adminsys;
		c_mediator_mock m_mediator_mock_organizer;
		const std::filesystem::path m_datadir_path = "./bc-many-txs";
		const std::filesystem::path m_wallet_path_adminsys = m_datadir_path / "adminsys_wallet";
		const std::filesystem::path m_wallet_path_organizer = m_datadir_path / "organizer_wallet";

		c_wallet m_organizer_wallet;

		std::unique_ptr<c_blockchain_module> m_blockchain_module_adminsys;
		std::unique_ptr<c_blockchain_module> m_blockchain_module_organizer;
};

blockchain_module_add_voting_protocols::blockchain_module_add_voting_protocols()
    :
#ifdef COVERAGE_TESTS
        m_number_protocols(2),
#elif IVOTING_TESTS
      m_number_protocols(25000),
#endif
      m_adminsys_keypair(generate_adminsys_keypair()),
      m_organizer_wallet(m_wallet_path_organizer)
{
	std::random_device rd;
	std::mt19937 gen(rd());
	std::string voting_protocol;
	for(size_t j=0; j<m_number_protocols; j++) {
		for(size_t i=0; i<10; i++) {
			std::uniform_int_distribution<> distribution(0, 1000);
			auto gen_char = distribution(gen);
			voting_protocol+=std::to_string(gen_char);
		}
		m_voting_protocols.push_back(voting_protocol);
		voting_protocol.erase();
	}
}

t_root_keypair blockchain_module_add_voting_protocols::generate_adminsys_keypair() const {
	n_bip32::c_key_manager_BIP32 key_manager(n_blockchainparams::entropy_seed);
	return key_manager.get_root_key();
}

boost::program_options::variables_map blockchain_module_add_voting_protocols::generate_variable_map(const std::filesystem::path & path) const {
	boost::program_options::variables_map variable_map;
	variable_map.insert(std::make_pair("par", boost::program_options::variable_value(static_cast<unsigned short>(1), false)));
	variable_map.insert(std::make_pair("gen", boost::program_options::variable_value()));
	variable_map.insert(std::make_pair("datadir", boost::program_options::variable_value(path, false)));
	variable_map.insert(std::make_pair("force-mine", boost::program_options::variable_value(false, false)));
	boost::program_options::notify(variable_map);
	return variable_map;
}

void blockchain_module_add_voting_protocols::setup_mediators() {
	setup_mediator(m_mediator_mock_adminsys, m_adminsys_keypair);
	setup_mediator(m_mediator_mock_organizer, m_organizer_wallet.get_main_keypair());
}

void blockchain_module_add_voting_protocols::setup_mediator(c_mediator_mock & mediator_mock, t_root_keypair keypair) {
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
								m_blockchain_module_organizer->add_new_block(request_broadcast_mediator.m_block);
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

void blockchain_module_add_voting_protocols::SetUp() {
	c_blockchain_module_builder blockchain_module_builder;
	{
	const auto variable_map = generate_variable_map(m_datadir_path/"adminsys");
	    blockchain_module_builder.set_program_options(variable_map);
		m_blockchain_module_adminsys = blockchain_module_builder.get_result(m_mediator_mock_adminsys);
	}
	{
		const auto variable_map = generate_variable_map(m_datadir_path/"organizer");
		blockchain_module_builder.set_program_options(variable_map);
		m_blockchain_module_organizer = blockchain_module_builder.get_result(m_mediator_mock_organizer);
	}
	setup_mediators();
}

void blockchain_module_add_voting_protocols::TearDown() {
	m_blockchain_module_adminsys->stop();
	std::filesystem::remove_all(m_datadir_path);
}

TEST_F(blockchain_module_add_voting_protocols, add_protocol) {
	m_blockchain_module_adminsys->run();
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)); // wait for next block
	auto txs_from_mempool = m_blockchain_module_adminsys->get_mempool_transactions();
	EXPECT_EQ(txs_from_mempool.size(), 0);
	const auto organizer_pk = m_organizer_wallet.get_main_pk();
	const auto organizer_auth_tx = m_blockchain_module_adminsys->authorize_organizer_by_adminsys(organizer_pk, m_adminsys_keypair.m_public_key);
	m_blockchain_module_adminsys->add_new_transaction(organizer_auth_tx);
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)); // wait for next block
	txs_from_mempool = m_blockchain_module_adminsys->get_mempool_transactions();
	EXPECT_EQ(txs_from_mempool.size(), 0);
	const auto txid_auth_organizer = m_blockchain_module_adminsys->get_auth_txid(organizer_pk);
	EXPECT_EQ(organizer_auth_tx.m_txid, txid_auth_organizer);
	t_hash_type txid_tmp;
	txid_tmp.fill(0x00);
	EXPECT_EQ(m_blockchain_module_adminsys->get_auth_txid(m_adminsys_keypair.m_public_key), txid_tmp);
	t_public_key_type pk_tmp;
	pk_tmp.fill(0x00);
	EXPECT_THROW(m_blockchain_module_adminsys->get_auth_txid(pk_tmp), std::invalid_argument);

	for(const auto & voting_protocol:m_voting_protocols) {
		const auto voting_protocol_vec = container_to_vector_of_uchars(voting_protocol);
		const auto tx_add_voting_protocol = m_blockchain_module_organizer->add_voting_protocol(voting_protocol_vec, organizer_pk);
		m_blockchain_module_adminsys->add_new_transaction(tx_add_voting_protocol);
	}

	const size_t multiplier_blocks = 10;
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec * multiplier_blocks)); // wait for next block
	m_blockchain_module_adminsys->stop(); // stop mining
	txs_from_mempool = m_blockchain_module_adminsys->get_mempool_transactions();
	EXPECT_EQ(txs_from_mempool.size(), 0);

	size_t number_of_found_protocols = 0;
	const auto all_hashes_of_voting_protocols = m_blockchain_module_adminsys->get_hashes_voting_protocols();
	for(const auto &hash_protocol:all_hashes_of_voting_protocols) {
		const auto tx_voting_protocol = m_blockchain_module_adminsys->get_tx_voting_protocol(hash_protocol);
		EXPECT_EQ(tx_voting_protocol.m_type, t_transactiontype::another_voting_protocol);
		const auto protocol = tx_voting_protocol.m_allmetadata;
		const auto it = std::find_if(m_voting_protocols.cbegin(), m_voting_protocols.cend(), [&protocol](const std::string & voting_protocol) {
			const auto voting_protocol_vec = container_to_vector_of_uchars(voting_protocol);
			return protocol==voting_protocol_vec;});
		if(it!=m_voting_protocols.cend()) number_of_found_protocols++;
	}
	EXPECT_EQ(number_of_found_protocols, m_number_protocols);
	EXPECT_EQ(number_of_found_protocols, m_voting_protocols.size());
	EXPECT_EQ(number_of_found_protocols, all_hashes_of_voting_protocols.size());
	
	const auto number_txs = m_blockchain_module_adminsys->get_number_of_transactions();
	EXPECT_EQ(number_txs, m_number_protocols+1);
	const auto id_block_with_organizer_auth_tx = m_blockchain_module_adminsys->get_block_id_by_txid(organizer_auth_tx.m_txid);
	const auto block_with_organizer_auth_tx = m_blockchain_module_adminsys->get_block_at_height(1);
	EXPECT_EQ(id_block_with_organizer_auth_tx, block_with_organizer_auth_tx.m_header.m_actual_hash);
	const auto bc_size = m_blockchain_module_adminsys->get_height();
	const size_t amount = multiplier_blocks + 2;
	const auto last_blocks = m_blockchain_module_adminsys->get_sorted_blocks(amount);
	for(size_t i=0; i<amount; i++) {
		const auto block = m_blockchain_module_adminsys->get_block_at_height(bc_size-i);
		const auto block_at_hash = m_blockchain_module_adminsys->get_block_at_hash(block.m_header.m_actual_hash);
		EXPECT_EQ(block, block_at_hash);
		std::vector<std::vector<t_hash_type>> merkle_branches;
		for(const auto & tx:block.m_transaction) {
			const auto block_by_txid = m_blockchain_module_adminsys->get_block_by_txid(tx.m_txid);
			EXPECT_EQ(block, block_by_txid);
			const auto block_id = m_blockchain_module_adminsys->get_block_id_by_txid(tx.m_txid);
			EXPECT_EQ(block.m_header.m_actual_hash, block_id);
			const auto merkle_branch = m_blockchain_module_adminsys->get_merkle_branch(tx.m_txid);
			merkle_branches.push_back(merkle_branch);
		}
		auto it = std::adjacent_find(merkle_branches.cbegin(), merkle_branches.cend());
		EXPECT_EQ(it, merkle_branches.cend());
		EXPECT_EQ(last_blocks.at(i).m_header, block.m_header);
		EXPECT_EQ(last_blocks.at(i).m_number_of_transactions, block.m_transaction.size());
		const auto number_of_offset =std::ceil(static_cast<double>(block.m_transaction.size()) / n_rpcparams::number_of_txs_from_block_per_page);
		std::vector< std::pair<std::vector<c_transaction>, size_t>> all_txs_per_page;
		for(size_t i=1; i<=static_cast<size_t>(number_of_offset); i++) {
			const auto txs_per_page = m_blockchain_module_adminsys->get_txs_from_block_per_page(i, block.m_header.m_actual_hash);
			EXPECT_EQ(txs_per_page.second, block.m_transaction.size());
			all_txs_per_page.push_back(txs_per_page);
		}
		auto iterator = std::adjacent_find(all_txs_per_page.cbegin(), all_txs_per_page.cend());
		EXPECT_EQ(iterator, all_txs_per_page.cend());
	}
	size_t offset = 1;
	const auto blocks_per_page = m_blockchain_module_adminsys->get_sorted_blocks_per_page(offset);
	EXPECT_EQ(blocks_per_page.second, bc_size);
	EXPECT_EQ(blocks_per_page.first.size(), n_rpcparams::number_of_blocks_per_page);
	for(size_t i=0; i<n_rpcparams::number_of_blocks_per_page; i++) {
		const auto block = m_blockchain_module_adminsys->get_block_at_height(bc_size-i);
		EXPECT_EQ(blocks_per_page.first.at(i).m_header, block.m_header);
		EXPECT_EQ(blocks_per_page.first.at(i).m_number_of_transactions, block.m_transaction.size());
	}
	size_t amount_txs = 5;
	auto last_txs = m_blockchain_module_adminsys->get_latest_transactions(amount_txs);
	if(number_txs<=n_rpcparams::number_of_txs_per_page) {
		offset = 1;
		const auto pair_txs_per_page_to_size = m_blockchain_module_adminsys->get_txs_per_page(offset);
		const auto txs_per_page = pair_txs_per_page_to_size.first;
		amount_txs = m_blockchain_module_adminsys->get_number_of_transactions();
		last_txs = m_blockchain_module_adminsys->get_latest_transactions(amount_txs);
		EXPECT_EQ(last_txs, txs_per_page);
	} else {
		offset = 1;
		auto pair_txs_per_page_to_size = m_blockchain_module_adminsys->get_txs_per_page(offset);
		auto txs_per_page = pair_txs_per_page_to_size.first;
		offset = 2;
		pair_txs_per_page_to_size = m_blockchain_module_adminsys->get_txs_per_page(offset);
		const auto txs_per_page_2 = pair_txs_per_page_to_size.first;
		std::copy(txs_per_page_2.cbegin(), txs_per_page_2.cend(), std::back_inserter(txs_per_page));
		amount_txs = 20;
		last_txs = m_blockchain_module_adminsys->get_latest_transactions(amount_txs);
		EXPECT_EQ(last_txs, txs_per_page);
	}
}
