#ifndef BLOCKCHAIN_MODULE_MOCK_HPP
#define BLOCKCHAIN_MODULE_MOCK_HPP

#include <gmock/gmock.h>
#include "../src/blockchain_module.hpp"
#include "mediator_stub.hpp"

class c_blockchain_module_mock : public c_blockchain_module {
	public:
		c_blockchain_module_mock();
		MOCK_METHOD(void, add_new_block, (const c_block & block), (override));
		MOCK_METHOD(bool, add_new_transaction, (const c_transaction & tx), (override));
		MOCK_METHOD(c_transaction, get_transaction, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(c_block, get_block_at_height, (const size_t height), (const, override));
		MOCK_METHOD(c_block, get_block_at_hash, (const t_hash_type & hash), (const, override));
		MOCK_METHOD(t_hash_type, get_last_block_hash, (), (const, override));
		MOCK_METHOD(size_t, get_number_of_mempool_transactions, (), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_mempool_transactions, (), (const, override));
		MOCK_METHOD(proto::block, get_block_at_hash_proto, (const t_hash_type & block_hash), (const, override));
		MOCK_METHOD(std::vector<proto::header>, get_headers_proto, (const t_hash_type & hash_begin, const t_hash_type & hash_end), (const, override));
		MOCK_METHOD(bool, is_pk_organizer, (const t_public_key_type & pk), (const, override));
		MOCK_METHOD(bool, is_pk_miner, (const t_public_key_type & pk), (const, override));
		MOCK_METHOD(size_t, get_height, (), (const, override));
		MOCK_METHOD(uint32_t, get_last_block_time, (), (const, override));
		MOCK_METHOD(c_block, get_block_by_txid, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(std::vector<t_hash_type>, get_merkle_branch, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(t_hash_type, get_block_id_by_txid, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(size_t, get_number_of_miners, (), (const, override));
		MOCK_METHOD(size_t, get_number_of_transactions, (), (const, override));
		MOCK_METHOD(std::vector<c_block_record>, get_sorted_blocks, (const size_t amount_of_blocks), (const, override));
		using vector_blocks_record_to_size = std::pair<std::vector<c_block_record>, size_t>;
		MOCK_METHOD(vector_blocks_record_to_size, get_sorted_blocks_per_page, (const size_t offset), (const, override));
		MOCK_METHOD(std::vector<c_transaction>, get_latest_transactions, (const size_t amount_txs), (const, override));
		using vector_transaction_to_size = std::pair<std::vector<c_transaction>, size_t>;
		MOCK_METHOD(vector_transaction_to_size, get_txs_per_page, (const size_t offset), (const, override));
		MOCK_METHOD(vector_transaction_to_size, get_txs_from_block_per_page, (const size_t offset, const t_hash_type &block_id), (const, override));
		using signature_to_pk_vector_to_size = std::pair<std::vector<std::pair<t_signature_type, t_public_key_type>>, size_t>;
		MOCK_METHOD(signature_to_pk_vector_to_size, get_block_signatures_and_pk_miners_per_page, (const size_t offset, const t_hash_type &block_id), (const, override));
		MOCK_METHOD(bool, is_transaction_in_blockchain, (const t_hash_type & txid), (const, override));
		MOCK_METHOD(c_transaction, authorize_organizer_by_adminsys, (const t_public_key_type &organizer_pk, const t_public_key_type &adminsys_pk), (override));
		MOCK_METHOD(c_transaction, authorize_miner_by_adminsys, (const t_public_key_type &miner_pk, const t_public_key_type &adminsys_pk), (override));
		MOCK_METHOD(bool, is_blockchain_synchronized, (), (const, override));
		MOCK_METHOD(c_transaction, add_voting_protocol, (const std::vector<unsigned char> & voting_protocol, const t_public_key_type & organizer_pk), (override));
		MOCK_METHOD(t_hash_type, get_auth_txid,(const t_public_key_type & pk), (const, override));
		MOCK_METHOD(bool, block_exists, (const t_hash_type & block_id), (const, override));
	private:
		static c_mediator_stub m_mediator_stub;
};

#endif // BLOCKCHAIN_MODULE_MOCK_HPP
