#include <gtest/gtest.h>
#include <algorithm>
#include <random>
#include "../src/transaction.hpp"
#include "../src/txid_generate.hpp"
#include "../src/serialization_utils.hpp"
#include "../src/utils.hpp"

class serialization_utils : public  ::testing::TestWithParam<std::tuple<unsigned int, unsigned int, unsigned int>>{
	protected:
		c_transaction get_random_tx(const size_t number_of_vin, const size_t number_of_vout) const;
		c_vout make_random_vout() const;
		c_vin make_random_vin() const;
	private:
		unsigned char get_random_byte() const;
		uint8_t get_random_int() const;
		std::random_device m_random_device;
};

c_vout serialization_utils::make_random_vout() const {
	c_vout vout;
	std::generate(vout.m_pkh.begin(), vout.m_pkh.end(), [this] {
		return get_random_byte();
	});
	vout.m_amount = get_random_int();
	return vout;
}

c_vin serialization_utils::make_random_vin() const {
	std::mt19937 generator;
	std::uniform_int_distribution<unsigned int> distribution(0U, 255U);
	c_vin vin;
	auto rand_byte_lambda = [this] {
		return get_random_byte();
	};
	std::generate(vin.m_txid.begin(), vin.m_txid.end(), rand_byte_lambda);
	std::generate(vin.m_sign.begin(), vin.m_sign.end(), rand_byte_lambda);
	std::generate(vin.m_pk.begin(), vin.m_pk.end(), rand_byte_lambda);
	return vin;
}

unsigned char serialization_utils::get_random_byte() const {
	return static_cast<unsigned char>(get_random_int());
}

uint8_t serialization_utils::get_random_int() const {
	static std::mt19937 generator;
	static std::uniform_int_distribution<uint8_t> distribution(0U, 255U);
	return distribution(generator);
}

c_transaction serialization_utils::get_random_tx(const size_t number_of_vin, const size_t number_of_vout) const {
	c_transaction transaction;
	transaction.m_type = t_transactiontype::add_secret_vote;
	for(size_t i=0; i<number_of_vout; i++) {
		auto vout = make_random_vout();
		transaction.m_vout.emplace_back(std::move(vout));
	}
	for(size_t i=0; i<number_of_vin; i++) {
		auto vin = make_random_vin();
		transaction.m_vin.emplace_back(std::move(vin));
	}
	return transaction;
}

INSTANTIATE_TEST_SUITE_P(serialization_and_deserialization, serialization_utils, testing::Combine(
						testing::Range(0u,100u),
						testing::Range(0u, 6u),
						testing::Range(0u, 6u)
));

TEST_P(serialization_utils, serialization_and_deserialization) {
	const auto number_of_vin = std::get<1>(GetParam());
	const auto number_of_vout = std::get<2>(GetParam());
	auto transaction = get_random_tx(number_of_vin, number_of_vout);
	auto txid = c_txid_generate::generate_txid(transaction);
	transaction.m_txid = txid;
	const auto serialize_transaction = serialize_to_string(transaction);
	const auto deserialize_transaction = deserialize_from_string<c_transaction>(serialize_transaction);
	EXPECT_EQ(transaction, deserialize_transaction);
}

INSTANTIATE_TEST_SUITE_P(protobuf, serialization_utils, testing::Combine(
						testing::Range(0u,100u),
						testing::Range(0u, 6u),
						testing::Range(0u, 6u)
));

TEST_P(serialization_utils, protobuf) {
	const auto number_of_vin = std::get<1>(GetParam());
	const auto number_of_vout = std::get<2>(GetParam());
	auto transaction = get_random_tx(number_of_vin, number_of_vout);
	auto txid = c_txid_generate::generate_txid(transaction);
	transaction.m_txid = txid;
	const auto to_protobuf_transaction = transaction_to_protobuf(transaction);
	const auto from_protobuf_transaction = transaction_from_protobuf(to_protobuf_transaction);
	EXPECT_EQ(transaction, from_protobuf_transaction);
}

TEST_P(serialization_utils, block) {
	const auto number_of_transactions = 10;
	c_block block;
	for (auto i = 0U; i < number_of_transactions; i++) {
		const auto number_of_vin = std::get<1>(GetParam());
		const auto number_of_vout = std::get<2>(GetParam());
		auto transaction = get_random_tx(number_of_vin, number_of_vout);
		auto txid = c_txid_generate::generate_txid(transaction);
		transaction.m_txid = txid;
		block.m_transaction.push_back(std::move(transaction));
	}
	block.m_header.m_block_time = static_cast<uint32_t>(get_unix_time());
	block.m_header.m_actual_hash.fill(0x76);
	block.m_header.m_parent_hash.fill(0x76);
	block.m_header.m_version = 0;
	block.m_header.m_all_signatures.emplace_back();

	const auto serialized_block = serialize_to_string(block);
	const auto deserialized_block = deserialize_from_string<c_block>(serialized_block);
	EXPECT_EQ(block.m_header.m_block_time, deserialized_block.m_header.m_block_time);
	EXPECT_EQ(block.m_header.m_actual_hash, deserialized_block.m_header.m_actual_hash);
	EXPECT_EQ(block.m_header.m_parent_hash, deserialized_block.m_header.m_parent_hash);
	EXPECT_EQ(block.m_header.m_version, deserialized_block.m_header.m_version);
	EXPECT_EQ(block.m_transaction, deserialized_block.m_transaction);
}

TEST_P(serialization_utils, vout) {
	const auto vout = make_random_vout();
	const auto serialized_vout = serialize_to_string(vout);
	const auto deserialized_vout = deserialize_from_string<c_vout>(serialized_vout);
	EXPECT_EQ(vout, deserialized_vout);
}

TEST_P(serialization_utils, vin) {
	const auto vin = make_random_vin();
	const auto serialized_vin = serialize_to_string(vin);
	const auto deserialized_vin = deserialize_from_string<c_vin>(serialized_vin);
	EXPECT_EQ(vin, deserialized_vin);
}

TEST_P(serialization_utils, block_record) {
	c_block_record block_record;
	block_record.m_header.m_block_time = static_cast<uint32_t>(get_unix_time());
	block_record.m_header.m_actual_hash.fill(0x76);
	block_record.m_header.m_parent_hash.fill(0x76);
	block_record.m_header.m_version = 0;
	block_record.m_header.m_all_signatures.emplace_back();
	block_record.m_height = std::get<0>(GetParam());
	block_record.m_number_of_transactions = std::get<1>(GetParam());
	block_record.m_file_contains_block = "test file name";
	block_record.m_position_in_file = static_cast<int>(std::get<2>(GetParam()));
	block_record.m_size_of_binary_data = std::get<2>(GetParam());
	const auto serialized_block_record = serialize_to_string(block_record);
	const auto deserialized_block_record = deserialize_from_string<c_block_record>(serialized_block_record);
	EXPECT_EQ(block_record.m_header.m_block_time, deserialized_block_record.m_header.m_block_time);
	EXPECT_EQ(block_record.m_header.m_actual_hash, deserialized_block_record.m_header.m_actual_hash);
	EXPECT_EQ(block_record.m_header.m_parent_hash, deserialized_block_record.m_header.m_parent_hash);
	EXPECT_EQ(block_record.m_header.m_version, deserialized_block_record.m_header.m_version);
	EXPECT_EQ(block_record.m_height, deserialized_block_record.m_height);
	EXPECT_EQ(block_record.m_number_of_transactions, deserialized_block_record.m_number_of_transactions);
	EXPECT_EQ(block_record.m_file_contains_block, deserialized_block_record.m_file_contains_block);
	EXPECT_EQ(block_record.m_position_in_file, deserialized_block_record.m_position_in_file);
	EXPECT_EQ(block_record.m_size_of_binary_data, deserialized_block_record.m_size_of_binary_data);
}
