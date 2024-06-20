#ifndef C_BLOCKCHAIN_MOCK_HPP
#define C_BLOCKCHAIN_MOCK_HPP

#include "../src/blockchain.hpp"
#include <gmock/gmock.h>

class c_blockchain_mock : public c_blockchain {
	public:
		c_blockchain_mock();
		MOCK_METHOD(c_block, get_block_at_hash, (const t_hash_type & block_id), (const, override));
		MOCK_METHOD(proto::block, get_block_at_hash_proto, (const t_hash_type & block_id), (const, override));
		MOCK_METHOD(c_block, get_block_by_txid, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(c_block, get_last_block, (), (const, override));
		MOCK_METHOD(size_t, get_number_of_transactions, (), (const, override));
		MOCK_METHOD(std::vector<c_block_record>, get_last_5_blocks, (), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_last_5_transactions, (), (const, override));
		MOCK_METHOD(std::vector<c_block_record>, get_sorted_blocks, (const size_t amount_of_blocks), (const, override));
		using blocks_to_size = std::pair<std::vector<c_block_record>, size_t>;
		MOCK_METHOD(blocks_to_size , get_sorted_blocks_per_page, (const size_t offset), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_latest_transactions, (const size_t amount_txs), (const, override));
		using transactions_to_size = std::pair<std::vector<c_transaction>, size_t>;
		MOCK_METHOD(transactions_to_size, get_txs_per_page, (const size_t offset), (const, override));
		MOCK_METHOD(transactions_to_size, get_txs_from_block_per_page, (const size_t offset, const t_hash_type & block_id), (const, override));
		MOCK_METHOD(t_hash_type, get_block_id_by_txid, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(std::vector<t_hash_type>, get_merkle_branch, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(c_transaction, get_transaction, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(c_block, get_block_at_height, (const size_t height), (const, override));
		MOCK_METHOD(size_t, get_current_height, (), (const, override));
		MOCK_METHOD(size_t, get_height_for_block_id, (const t_hash_type & block_id), (const, override));
		MOCK_METHOD(proto::header, get_header_proto, (const t_hash_type & block_id), (const, override));
};

#endif // C_BLOCKCHAIN_MOCK_HPP
