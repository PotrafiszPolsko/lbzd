#ifndef BLOCKCHAIN_HPP
#define BLOCKCHAIN_HPP
#include "block.hpp"
#include "types.hpp"
#include <filesystem>
#include <sstream>
#include <fstream>
#include <memory>
#include <leveldb/db.h>
#include "block_record.hpp"
#include "p2p.pb.h" // for proto types
#include "blockchain.pb.h" // for proto types

class c_blockchain {
	public:
		c_blockchain() = default; //only for tests
		c_blockchain(const std::filesystem::path & datadir_path);
		virtual ~c_blockchain() = default;
		/**
		 * @throws std::runtime_error if blockchain hasn't blocks
		 * @return newest block
		 */
		virtual c_block get_last_block() const;
		void add_block(const c_block & block);
		/**
		 * @throws std::runtime_error if not found transaction
		 * @return transaction with given txid
		 */
		virtual c_transaction get_transaction(const t_hash_type & txid) const;
		bool is_transaction_in_blockchain(const t_hash_type & txid) const;
		size_t get_number_of_blocks() const noexcept;
		virtual c_block get_block_at_height(const size_t height) const;
		virtual c_block get_block_at_hash(const t_hash_type & block_id) const;
		virtual proto::block get_block_at_hash_proto(const t_hash_type & block_id) const;
		virtual c_block get_block_by_txid(const t_hash_type & txid) const;
		std::vector<c_block> get_blocks() const;
		virtual size_t get_height_for_block_id(const t_hash_type & block_id) const;
		virtual size_t get_current_height() const;
		virtual proto::header get_header_proto(const t_hash_type & block_id) const;
		bool block_exists(const t_hash_type & block_id) const;
		virtual std::vector<t_hash_type> get_merkle_branch(const t_hash_type & txid) const;
		virtual t_hash_type get_block_id_by_txid(const t_hash_type & txid) const;
		virtual size_t get_number_of_transactions() const;
		virtual std::vector<c_block_record> get_last_5_blocks() const;
		virtual std::vector<c_transaction> get_last_5_transactions() const;
		virtual std::vector<c_block_record> get_sorted_blocks(const size_t amount_of_blocks) const;
		virtual std::pair<std::vector<c_block_record>, size_t> get_sorted_blocks_per_page(const size_t offset) const;
		virtual std::vector<c_transaction> get_latest_transactions(const size_t amount_txs) const;
		virtual std::pair<std::vector<c_transaction>, size_t> get_txs_per_page(const size_t offset) const;
		virtual std::pair<std::vector<c_transaction>, size_t> get_txs_from_block_per_page(const size_t offset, const t_hash_type & block_id) const;
	private:
		static constexpr unsigned long s_max_size_of_block_file = 128 * 1024 * 1024;
		std::filesystem::path m_datadir_path;
		std::filesystem::path m_blocks_dir_path;
		mutable std::unique_ptr<leveldb::DB> m_blocks_database;

		void create_dir_tree();
		void open_blocks_db() const;
		size_t get_last_blockfile_number() const;
		void increment_last_blockfile_number() const;
		std::filesystem::path get_block_filename_for_save(size_t file_number, size_t block_as_binary_string_size) const;
		void save_block_record(c_block_record & block_record);
		void save_file_information(size_t file_number, const std::filesystem::path & block_filename);
		void write_last_block_file_number(size_t file_number);
		std::filesystem::path get_block_filename(size_t file_number) const;
		proto::block read_block_from_ifstream_proto(std::ifstream & block_file) const;
		c_block_record get_block_record(const t_hash_type & block_id) const;
		proto::block_record get_block_record_proto(const t_hash_type & block_id) const;
		size_t get_file_number_from_blk_path(const std::filesystem::path & block_filename) const;
		void save_current_height(size_t height);
		std::string get_block_record_as_string(const t_hash_type& block_id) const;
		std::vector<c_block_record> get_all_sorted_record_blocks(const size_t current_height) const;
		std::vector<c_block_record> get_sorted_record_blocks_with_txs_only() const;
};

#endif // BLOCKCHAIN_HPP
