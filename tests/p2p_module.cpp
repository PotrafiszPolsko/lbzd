#include "../src/p2p_module.hpp"
#include "../src/serialization_utils.hpp"
#include "../src/utils.hpp"
#include "p2p_module_mock.hpp"
#include "mediator_mock.hpp"
#include "p2p_module_builder_tests.hpp"
#include "p2p_session_manager_tcp_mock.hpp"
#include "p2p_session_manager_tor_mock.hpp"
#include "peer_finder_mock.hpp"
#include "port_forwarder_mock.hpp"

class p2p_module : public ::testing::Test {
	protected:
		c_mediator_mock m_mediator_mock;
};

TEST_F(p2p_module, send_proto_message_to_peer_parse_block) {
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
	
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillRepeatedly(
	            [&block, &parent_hash](const t_mediator_command_request & request){
		            std::unique_ptr<t_mediator_command_response> response;
					switch (request.m_type) {
						case t_mediator_cmd_type::e_add_new_block:
						{
							const auto request_add_new_block = dynamic_cast<const t_mediator_command_request_add_new_block&>(request);
							EXPECT_EQ(request_add_new_block.m_block, block);
							response = std::make_unique<t_mediator_command_response_add_new_block>();
							break;
						}
						case t_mediator_cmd_type::e_get_last_block_hash:
						{
							const auto request_get_last_block_hash = dynamic_cast<const t_mediator_command_request_get_last_block_hash&>(request);
							response = std::make_unique<t_mediator_command_response_get_last_block_hash>();
							auto & response_last_block_hash = dynamic_cast<t_mediator_command_response_get_last_block_hash&>(*response);
							response_last_block_hash.m_last_block_hash = parent_hash;
							break;
						}
						default:
						break;
					}
					assert(response != nullptr);
					return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	auto * const block_proto = proto_message.mutable_m_block();
	*block_proto = block_to_protobuf(block);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_headers) {
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

	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
			.WillRepeatedly(
				[&actual_hash](const t_mediator_command_request & request) {
					std::unique_ptr<t_mediator_command_response> response;
					switch (request.m_type) {
						case t_mediator_cmd_type::e_is_blockchain_synchronized:
						{
							response = std::make_unique<t_mediator_command_response_is_blockchain_synchronized>();
							auto & response_is_bc_synchronized = dynamic_cast<t_mediator_command_response_is_blockchain_synchronized&>(*response);
							response_is_bc_synchronized.m_is_blockchain_synchronized = false;
							break;
						}
						case t_mediator_cmd_type::e_block_exists:
						{
							response = std::make_unique<t_mediator_command_response_block_exists>();
							auto & response_block_exists = dynamic_cast<t_mediator_command_response_block_exists&>(*response);
							response_block_exists.m_block_exists = true;
							break;
						}
						case t_mediator_cmd_type::e_get_last_block_hash:
						{
							response = std::make_unique<t_mediator_command_response_get_last_block_hash>();
							auto & response_get_last_block_hash = dynamic_cast<t_mediator_command_response_get_last_block_hash&>(*response);
							response_get_last_block_hash.m_last_block_hash = actual_hash;
							break;
						}
						default:
							break;
					}
					return response;
				}
			);

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	auto * const headers_proto = proto_message.mutable_m_headers();
	auto * const new_header = headers_proto->add_m_headers();
	auto header_proto = header_to_protobuf(header);
	new_header->Swap(&header_proto);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_merkle_branch) {
	t_hash_type block_id;
	const std::string block_id_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(block_id_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad block_id size");
	int ret = 1;
	ret = sodium_hex2bin(block_id.data(), block_id.size(),
						block_id_str.data(), block_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type hash_1;
	const std::string hash_1_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(hash_1_str.size()!=hash_1.size()*2) throw std::invalid_argument("Bad hash size");
	ret = sodium_hex2bin(hash_1.data(), hash_1.size(),
						hash_1_str.data(), hash_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type hash_2;
	const std::string hash_2_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(hash_2_str.size()!=hash_2.size()*2) throw std::invalid_argument("Bad hash size");
	ret = sodium_hex2bin(hash_2.data(), hash_2.size(),
						hash_2_str.data(), hash_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);

	const auto hash_1_str_to_proto = container_to_string(hash_1);
	const auto hash_2_str_to_proto = container_to_string(hash_2);
	proto::merkle_branch merkle_branch;
	merkle_branch.add_m_merkle_branch(hash_1_str_to_proto);
	merkle_branch.add_m_merkle_branch(hash_2_str_to_proto);
	const auto block_id_str_to_proto = container_to_string(block_id);
	merkle_branch.set_m_block_id(block_id_str_to_proto);
	proto::proto_massage proto_message;
	proto_message.mutable_m_merkle_branch()->CopyFrom(merkle_branch);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_addr) {
	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string my_address = "91.236.233.26:22083";
	const auto &peer_finder = dynamic_cast<const c_peer_finder_mock&>(*p2p_module->m_peer_finder);
	EXPECT_CALL(peer_finder, is_my_address(my_address))
	        .WillOnce(
	            [&my_address](const std::string &address_tmp){return my_address==address_tmp;});

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::addr addr;
	auto * const proto_peer_details = addr.add_m_peer_list();
	proto_peer_details->set_m_address(address_tcp_str);
	proto_peer_details->set_m_port(port);
	proto_peer_details->set_m_timestamp(1679189050);
	proto::proto_massage proto_message;
	proto_message.mutable_m_addr()->CopyFrom(addr);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_gettx) {
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
	t_hash_type txid;
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_txid = txid;
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
	const std::string tx_vin_txid_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
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
	
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&txid, &tx](const t_mediator_command_request & request){
						const auto request_gettx = dynamic_cast<const t_mediator_command_request_get_tx &>(request);
						EXPECT_EQ(request_gettx.m_txid, txid);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_tx>();
						auto & response_gettx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
						response_gettx.m_transaction = tx;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto txid_str_to_proto = container_to_string(txid);
	request.mutable_m_gettxs()->set_m_hash_header(txid_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getblock) {
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
	const auto block_proto = block_to_protobuf(block);
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&actual_hash, &block_proto](const t_mediator_command_request & request){
						const auto request_getblock = dynamic_cast<const t_mediator_command_request_get_block_by_id_proto &>(request);
						EXPECT_EQ(request_getblock.m_block_hash , actual_hash);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_block_by_id_proto>();
						auto & response_getblock = dynamic_cast<t_mediator_command_response_get_block_by_id_proto&>(*response);
						response_getblock.m_block_proto = block_proto;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto actual_hash_str_to_proto = container_to_string(actual_hash);
	request.mutable_m_getblock()->set_m_hash_header(actual_hash_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getheaders) {
	c_header header_1;
	t_hash_type actual_hash;
	std::string actual_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	int ret = 1;
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_1.m_actual_hash = actual_hash;
	t_hash_type hash_begin = actual_hash;
	std::vector<t_signature_type> all_signatures;
	all_signatures.resize(1);
	std::string all_signatures_str = "5f7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_1.m_all_signatures = all_signatures;
	t_hash_type all_tx_hash;
	std::string all_tx_hash_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_1.m_all_tx_hash = all_tx_hash;
	header_1.m_block_time = 1679079676;
	t_hash_type parent_hash;
	std::string parent_hash_str = "5831afc6d532161290b235fe952e2c432ba7fbf7ee7f901bea6dc574019fd469";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_1.m_parent_hash = parent_hash;
	header_1.m_version = 0;
	c_header header_2;
	actual_hash_str = "aa677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(actual_hash_str.size()!=actual_hash.size()*2) throw std::invalid_argument("Bad actual hash size");
	ret = sodium_hex2bin(actual_hash.data(), actual_hash.size(),
						actual_hash_str.data(), actual_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_2.m_actual_hash = actual_hash;
	t_hash_type hash_end = actual_hash;
	all_signatures.resize(1);
	all_signatures_str = "aa7d1f487d65d7f4c8467deed197fcdedc3515054fbc71742b3cda9b0d8a5c2a296c57e97233dafdc5477b6190e2add39d684f7c503f311c27b01891ab05230e";
	if(all_signatures_str.size()!=all_signatures.at(0).size()*2) throw std::invalid_argument("Bad all_signatures size");
	ret = sodium_hex2bin(all_signatures.at(0).data(), all_signatures.at(0).size(),
						all_signatures_str.data(), all_signatures_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_2.m_all_signatures = all_signatures;
	all_tx_hash_str = "aaeab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(all_tx_hash_str.size()!=all_tx_hash.size()*2) throw std::invalid_argument("Bad all_tx_hash size");
	ret = sodium_hex2bin(all_tx_hash.data(), all_tx_hash.size(),
						all_tx_hash_str.data(), all_tx_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_2.m_all_tx_hash = all_tx_hash;
	header_2.m_block_time = 1679079676;
	parent_hash_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
	if(parent_hash_str.size()!=parent_hash.size()*2) throw std::invalid_argument("Bad parent hash size");
	ret = sodium_hex2bin(parent_hash.data(), parent_hash.size(),
						parent_hash_str.data(), parent_hash_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	header_2.m_parent_hash = parent_hash;
	header_2.m_version = 0;
	const auto header_1_proto = header_to_protobuf(header_1);
	const auto header_2_proto = header_to_protobuf(header_2);
	std::vector<proto::header> proto_headers;
	proto_headers.push_back(header_1_proto);
	proto_headers.push_back(header_2_proto);
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&hash_begin, &hash_end, &proto_headers](const t_mediator_command_request & request){
						const auto request_getheaders = dynamic_cast<const t_mediator_command_request_get_headers_proto &>(request);
						EXPECT_EQ(request_getheaders.m_hash_begin , hash_begin);
						EXPECT_EQ(request_getheaders.m_hash_end , hash_end);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_headers_proto>();
						auto & response_getheaders = dynamic_cast<t_mediator_command_response_get_headers_proto&>(*response);
						response_getheaders.m_headers = proto_headers;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto hash_begin_str_to_proto = container_to_string(hash_begin);
	const auto hash_end_str_to_proto = container_to_string(hash_end);
	request.mutable_m_getheaders()->set_m_hash_header_start(hash_begin_str_to_proto);
	request.mutable_m_getheaders()->set_m_hash_header_stop(hash_end_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getmempooltransactions) {
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
	const std::string tx_vin_txid_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
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
	std::vector<c_transaction>txs;
	txs.push_back(tx);
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&txs](const t_mediator_command_request & request){
						const auto request_getmempooltransactions = dynamic_cast<const t_mediator_command_request_get_mempool_transactions &>(request);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_mempool_transactions>();
						auto & response_getmempooltransactions = dynamic_cast<t_mediator_command_response_get_mempool_transactions&>(*response);
						response_getmempooltransactions.m_transactions = txs;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	request.mutable_m_getmempooltransactions();
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getmerklebranch) {
	t_hash_type txid;
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	int ret = 1;
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type hash_1;
	const std::string hash_1_str = "fcefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(hash_1_str.size()!=hash_1.size()*2) throw std::invalid_argument("Bad hash size");
	ret = sodium_hex2bin(hash_1.data(), hash_1.size(),
						hash_1_str.data(), hash_1_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type hash_2;
	const std::string hash_2_str = "aaefd000c7a8e644835c9bdf252d81135a375f72101f164b6a75b18019e3d53e";
	if(hash_2_str.size()!=hash_2.size()*2) throw std::invalid_argument("Bad hash size");
	ret = sodium_hex2bin(hash_2.data(), hash_2.size(),
						hash_2_str.data(), hash_2_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type block_id;
	const std::string block_id_str = "2ba3904dde8c813670a64d96d5614a6c90d6a94d692e1d839621e7d0aefaceb3";
	if(block_id_str.size()!=block_id.size()*2) throw std::invalid_argument("Bad block_id size");
	ret = sodium_hex2bin(block_id.data(), block_id.size(),
						block_id_str.data(), block_id_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	std::vector<t_hash_type> merkle_branch;
	merkle_branch.push_back(hash_1);
	merkle_branch.push_back(hash_2);
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&txid, &merkle_branch, &block_id](const t_mediator_command_request & request){
						const auto request_getmerklebranch = dynamic_cast<const t_mediator_command_request_get_merkle_branch &>(request);
						EXPECT_EQ(request_getmerklebranch.m_txid, txid);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_merkle_branch>();
						auto & response_getmerklebranch = dynamic_cast<t_mediator_command_response_get_merkle_branch&>(*response);
						response_getmerklebranch.m_block_id = block_id;
						response_getmerklebranch.m_merkle_branch = merkle_branch;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto txid_str_to_proto = container_to_string(txid);
	request.mutable_m_getmerklebranch()->set_m_txid(txid_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getallactivevotingsforvoter) {
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
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&voter_pk, &active_votings](const t_mediator_command_request & request){
						const auto request_getallactivevotingsforvoter = dynamic_cast<const t_mediator_command_request_get_all_active_votings_for_voter&>(request);
						EXPECT_EQ(request_getallactivevotingsforvoter.m_voter_pk, voter_pk);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_all_active_votings_for_voter>();
						auto & response_getallactivevotingsforvoter = dynamic_cast<t_mediator_command_response_get_all_active_votings_for_voter&>(*response);
						response_getallactivevotingsforvoter.m_active_votings = active_votings;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto voter_pk_str_to_proto = container_to_string(voter_pk);
	request.mutable_m_get_all_active_votings_for_voter()->set_m_voter_pk(voter_pk_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getamountonpkh) {
	t_hash_type pkh;
	const std::string pkh_str = "d4debcb364a14025b13640899929abc31484797e4b6eaf788fba6833ec6fcc92";
	if(pkh_str.size()!=pkh.size()*2) throw std::invalid_argument("Bad pkh size");
	int ret = 1;
	ret = sodium_hex2bin(pkh.data(), pkh.size(),
						pkh_str.data(), pkh_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	t_hash_type txid;
	const std::string txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						txid_str.data(), txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillRepeatedly(
	            [&pkh, &txid](const t_mediator_command_request & request){
					std::unique_ptr<t_mediator_command_response> response;
					switch (request.m_type) {
						case t_mediator_cmd_type::e_get_amount_on_pkh:
						{
							const auto request_getamountonpkh = dynamic_cast<const t_mediator_command_request_get_amount_on_pkh&>(request);
							EXPECT_EQ(request_getamountonpkh.m_pkh, pkh);
							response = std::make_unique<t_mediator_command_response_get_amount_on_pkh>();
							auto & response_getamountonpkh = dynamic_cast<t_mediator_command_response_get_amount_on_pkh&>(*response);
							response_getamountonpkh.m_amount = 1;
							break;
						}
						case t_mediator_cmd_type::e_get_source_txid_for_pkh:
						{
							const auto request_getsourcetxidforpkh = dynamic_cast<const t_mediator_command_request_get_source_txid_for_pkh&>(request);
							EXPECT_EQ(request_getsourcetxidforpkh.m_pkh, pkh);
							response = std::make_unique<t_mediator_command_response_get_source_txid_for_pkh>();
							auto & response_getsourcetxidforpkh = dynamic_cast<t_mediator_command_response_get_source_txid_for_pkh&>(*response);
							response_getsourcetxidforpkh.m_txid = txid;
							break;
						}
						default:
						break;
					}
					assert(response != nullptr);
					return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto pkh_str_to_proto = container_to_string(pkh);
	request.mutable_m_get_amount_on_pkh()->set_m_pkh(pkh_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_gettransaction) {
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
	t_hash_type txid;
	const std::string tx_txid_str = "8ceab7910abf80c8d9c95a5937f9bdaadd17cef4a4077c6be33115071b03566d";
	if(tx_txid_str.size()!=txid.size()*2) throw std::invalid_argument("Bad txid size");
	ret = sodium_hex2bin(txid.data(), txid.size(),
						tx_txid_str.data(), tx_txid_str.size(),
						nullptr, nullptr, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
	tx.m_txid = txid;
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
	const std::string tx_vin_txid_str = "43677e6f5b952d27f4ef0828a38db971218e4b04a685bf64576a9ed2bad46abe";
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
	
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&txid, &tx](const t_mediator_command_request & request){
						const auto request_gettx = dynamic_cast<const t_mediator_command_request_get_tx &>(request);
						EXPECT_EQ(request_gettx.m_txid, txid);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_tx>();
						auto & response_gettx = dynamic_cast<t_mediator_command_response_get_tx&>(*response);
						response_gettx.m_transaction = tx;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto txid_str_to_proto = container_to_string(txid);
	request.mutable_m_get_transaction()->set_m_txid(txid_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getauthtxid) {
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
	using testing::_;
	EXPECT_CALL(m_mediator_mock, notify(_))
	        .WillOnce(
	            [&voting_id, &voter_pk, &txid](const t_mediator_command_request & request){
						const auto request_getauthtxid = dynamic_cast<const t_mediator_command_request_get_voter_auth_txid_for_voting&>(request);
						EXPECT_EQ(request_getauthtxid.m_voter_pk, voter_pk);
						EXPECT_EQ(request_getauthtxid.m_voting_id, voting_id);
						std::unique_ptr<t_mediator_command_response> response;
						response = std::make_unique<t_mediator_command_response_get_voter_auth_txid_for_voting>();
						auto & response_getauthtxid = dynamic_cast<t_mediator_command_response_get_voter_auth_txid_for_voting&>(*response);
						response_getauthtxid.m_txid = txid;
						assert(response != nullptr);
						return response;
	});

	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);

	std::string address_tcp_str = "91.236.233.26";
	unsigned short port = 22083;
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	const auto voter_pk_str_to_proto = container_to_string(voter_pk);
	const auto voting_id_str_to_proto = container_to_string(voting_id);
	request.mutable_m_get_authorization_txid()->set_m_pk(voter_pk_str_to_proto);
	request.mutable_m_get_authorization_txid()->set_m_voting_id(voting_id_str_to_proto);
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}

TEST_F(p2p_module, send_proto_message_to_peer_parse_request_getaddr) {
	c_p2p_module_builder_tests p2p_module_builder_test;
	const auto p2p_module = p2p_module_builder_test.build_p2p_module(m_mediator_mock);
	auto &peer_finder = dynamic_cast<c_peer_finder_mock&>(*p2p_module->m_peer_finder);

	t_peer_finder_address peer_address;
	peer_address.m_external_address = "91.236.233.26";
	peer_address.m_port = 22083;
	peer_address.m_timestamp = 1679189050;
	std::vector<t_peer_finder_address> peers_addresses;
	peers_addresses.push_back(peer_address);
	using ::testing::Return;
	EXPECT_CALL(peer_finder, load_peers())
	        .WillOnce(Return(peers_addresses));

	auto &port_forwarder = dynamic_cast<c_port_forwarder_mock&>(*p2p_module->m_port_forwarder);
	const auto address = std::make_pair(peer_address.m_external_address, peer_address.m_port);
	std::optional<std::pair<std::string, unsigned short>> opt_addr;
	opt_addr = address;
	EXPECT_CALL(port_forwarder, get_my_public_ip())
	        .WillOnce(Return(opt_addr));

	const auto &session_manager_tor = dynamic_cast<const c_p2p_session_manager_tor_mock&>(*p2p_module->m_session_manager_tor);
	const std::string address_tor_str = "jzn4p5ujyz74gqjpexxs7fidlsqmqqm4uefrj24ei35mwf4jlaajzja.onion";
	EXPECT_CALL(session_manager_tor, get_tor_address())
	        .WillOnce(Return(address_tor_str));
	unsigned short port = 22083;
	EXPECT_CALL(session_manager_tor, get_hidden_service_port())
	        .WillOnce(Return(port));

	std::string address_tcp_str = "91.236.233.26";
	auto peer_ref_from_tcp = create_peer_reference(address_tcp_str, port);
	proto::proto_massage proto_message;
	proto::request request;
	request.mutable_m_getaddr();
	proto_message.mutable_m_request()->CopyFrom(request);
	const auto proto_message_str = proto_message.SerializeAsString();
	const auto proto_message_vec = container_to_vector_of_uchars(proto_message_str);
	EXPECT_NO_THROW(p2p_module->read_handler_tcp(*peer_ref_from_tcp, span(proto_message_vec.data(), proto_message_vec.size())));
}
