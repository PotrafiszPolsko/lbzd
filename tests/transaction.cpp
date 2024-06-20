#include <gtest/gtest.h>
#include <algorithm>
#include <random>
#include "../src/transaction.hpp"
#include "../src/txid_generate.hpp"

class transaction : public ::testing::Test {
	protected:
		c_transaction m_transaction_1;
		c_transaction m_transaction_2;
		void SetUp() override;
		c_vout make_random_vout() const;
		c_vin make_random_vin() const;
	private:
		unsigned char get_random_byte() const;
		uint16_t get_random_int() const;
		c_transaction get_random_normal_tx() const;
		std::random_device m_random_device;
};

c_vout transaction::make_random_vout() const {
	c_vout vout;
	std::generate(vout.m_pkh.begin(), vout.m_pkh.end(), [this] {
		return get_random_byte();
	});
	vout.m_amount = get_random_int();
	return vout;
}

c_vin transaction::make_random_vin() const {
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

unsigned char transaction::get_random_byte() const {
	return static_cast<unsigned char>(get_random_int());
}

uint16_t transaction::get_random_int() const {
	static std::mt19937 generator;
	static std::uniform_int_distribution<uint16_t> distribution(0U, 255U);
	return distribution(generator);
}

c_transaction transaction::get_random_normal_tx() const {
	c_transaction transaction;
	transaction.m_type = t_transactiontype::add_secret_vote;
	auto vout = make_random_vout();
	transaction.m_vout.emplace_back(std::move(vout));
	auto vin = make_random_vin();
	transaction.m_vin.emplace_back(std::move(vin));
	return transaction;
}

void transaction::SetUp() {
	m_transaction_1 = get_random_normal_tx();
	m_transaction_2 = get_random_normal_tx();
}

TEST_F(transaction, txid_deterministic) {
	m_transaction_1.m_txid.fill(0x00);
	auto txid_1 = c_txid_generate::generate_txid(m_transaction_1);
	auto txid_2 = c_txid_generate::generate_txid(m_transaction_1);
	EXPECT_EQ(txid_1, txid_2);
	std::array<unsigned char, crypto_generichash_BYTES> txid_zeros;
	txid_zeros.fill(0x00);
	EXPECT_NE(txid_1, txid_zeros);
}

TEST_F(transaction, not_same_txid) {
	auto txid_1 = c_txid_generate::generate_txid(m_transaction_1);
	auto txid_2 = c_txid_generate::generate_txid(m_transaction_2);
	EXPECT_NE(txid_1, txid_2);
}

TEST_F(transaction, eq_txs) {
	EXPECT_EQ(m_transaction_1, m_transaction_1);
	EXPECT_EQ(m_transaction_2, m_transaction_2);
	EXPECT_NE(m_transaction_1, m_transaction_2);
}

TEST_F(transaction, swap_places_vin_vout) {
	c_transaction transaction_1;
	transaction_1.m_type = t_transactiontype::add_secret_vote;
	transaction_1.m_txid.fill(0x00);
	transaction_1.m_allmetadata.clear();
	auto transaction_2 = transaction_1;
	transaction_1.m_vout.clear();
	transaction_1.m_vin.clear();
	transaction_2.m_vout.clear();
	transaction_2.m_vin.clear();
	EXPECT_EQ(transaction_1, transaction_2);

	const auto vout_1 = make_random_vout();
	const auto vout_2 = make_random_vout();
	transaction_1.m_vout.emplace_back(vout_1);
	transaction_1.m_vout.emplace_back(vout_2);
	transaction_2.m_vout.emplace_back(vout_2);
	transaction_2.m_vout.emplace_back(vout_1);
	EXPECT_EQ(transaction_1, transaction_2);
	transaction_1.m_vout.clear();
	transaction_2.m_vout.clear();

	const auto vin_1 = make_random_vin();
	const auto vin_2 = make_random_vin();
	transaction_1.m_vin.emplace_back(vin_1);
	transaction_1.m_vin.emplace_back(vin_2);
	transaction_2.m_vin.emplace_back(vin_2);
	transaction_2.m_vin.emplace_back(vin_1);
	EXPECT_EQ(transaction_1, transaction_2);
	transaction_1.m_vin.clear();
	transaction_2.m_vin.clear();


	transaction_1.m_vout.emplace_back(vout_1);
	transaction_1.m_vout.emplace_back(vout_2);
	transaction_2.m_vout.emplace_back(vout_1);
	transaction_2.m_vout.emplace_back(vout_2);
	EXPECT_EQ(transaction_1, transaction_2);
	transaction_1.m_vout.clear();
	transaction_2.m_vout.clear();

	transaction_1.m_vin.emplace_back(vin_1);
	transaction_1.m_vin.emplace_back(vin_2);
	transaction_2.m_vin.emplace_back(vin_1);
	transaction_2.m_vin.emplace_back(vin_2);
	EXPECT_EQ(transaction_1, transaction_2);

	transaction_1.m_vout.emplace_back(vout_1);
	transaction_1.m_vout.emplace_back(vout_2);
	transaction_2.m_vout.emplace_back(vout_1);
	transaction_2.m_vout.emplace_back(vout_2);
	EXPECT_EQ(transaction_1, transaction_2);
	transaction_2.m_vout.clear();
	transaction_2.m_vin.clear();

	transaction_2.m_vin.emplace_back(vin_2);
	transaction_2.m_vin.emplace_back(vin_1);
	transaction_2.m_vout.emplace_back(vout_2);
	transaction_2.m_vout.emplace_back(vout_1);
	EXPECT_EQ(transaction_1, transaction_2);
	transaction_2.m_vout.clear();

	transaction_2.m_vout.emplace_back(vout_1);
	transaction_2.m_vout.emplace_back(vout_2);
	EXPECT_EQ(transaction_1, transaction_2);
	transaction_2.m_vout.clear();
	transaction_2.m_vin.clear();

	transaction_2.m_vin.emplace_back(vin_1);
	transaction_2.m_vin.emplace_back(vin_2);
	transaction_2.m_vout.emplace_back(vout_2);
	transaction_2.m_vout.emplace_back(vout_1);
	EXPECT_EQ(transaction_1, transaction_2);
}
