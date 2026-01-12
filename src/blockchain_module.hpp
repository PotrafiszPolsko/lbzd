#ifndef BLOCKCHAIN_MODULE_HPP
#define BLOCKCHAIN_MODULE_HPP

#include "component.hpp"
#include "blockchain.hpp"
#include "block_verifier.hpp"
#include "utxo.hpp"
#include "mempool.hpp"
#include "miner.hpp"
#include <shared_mutex>
#include <thread>
#include <tuple>
#include <optional>

class c_blockchain_module : public c_component {
	friend class c_blockchain_module_builder;
	friend std::unique_ptr<c_blockchain_module> std::make_unique<c_blockchain_module>(c_mediator &);
	public:
	~c_blockchain_module() override;
		virtual c_block get_block_at_height(size_t height) const;
		virtual c_block get_block_at_hash(const t_hash_type & block_id) const;
		virtual proto::block get_block_at_hash_proto(const t_hash_type & block_id) const;
		virtual c_block get_block_by_txid(const t_hash_type & txid) const;
		virtual c_transaction get_transaction(const t_hash_type & txid) const;
		virtual bool is_transaction_in_blockchain(const t_hash_type & txid) const;
		/**
		 * @return headers (m_hash_begin; m_hash_end]
		 * if m_hash_end is 0-filled get many headers as possible (max 200)
		 */
		virtual std::vector<proto::header> get_headers_proto(const t_hash_type & hash_begin, const t_hash_type & hash_end) const;
		virtual size_t get_height() const;
		virtual t_hash_type get_last_block_hash() const;
		virtual uint32_t get_last_block_time() const;
		virtual void add_new_block(const c_block & block);
		/**
		 * @brief add_new_transaction
		 * @return true when new transaction was added to mempool
		 * otherwise (tx found in mempool or blockchain) return false
		 */
		virtual bool add_new_transaction(const c_transaction & transaction);
		virtual size_t get_number_of_mempool_transactions() const;
		virtual std::vector<c_transaction> get_mempool_transactions() const;
		std::tuple<c_blockchain *, std::shared_mutex *, c_utxo *> get_blockchain_ref(); // for simulation only!
		void run() override;
		void stop();
		virtual bool is_pk_organizer(const t_public_key_type & pk) const;
		virtual bool is_pk_miner(const t_public_key_type & pk) const;
		virtual c_transaction authorize_organizer_by_adminsys(const t_public_key_type &organizer_pk, const t_public_key_type &adminsys_pk);
		virtual c_transaction authorize_miner_by_adminsys(const t_public_key_type &miner_pk, const t_public_key_type &adminsys_pk);
		/**
		 * @brief get_source_tx
		 * @return txid of transaction containing vout with given pkh
		 */
		virtual std::vector<t_hash_type> get_merkle_branch(const t_hash_type & txid) const;
		virtual t_hash_type get_block_id_by_txid(const t_hash_type & txid) const;
		virtual bool is_blockchain_synchronized() const;
		virtual size_t get_number_of_miners() const;
		virtual size_t get_number_of_transactions() const;
		virtual std::vector<c_block_record> get_sorted_blocks(const size_t amount_of_blocks) const;
		virtual std::pair<std::vector<c_block_record>, size_t> get_sorted_blocks_per_page(const size_t offset) const;
		virtual std::vector<c_transaction> get_latest_transactions(const size_t amount_txs) const;
		virtual std::pair<std::vector<c_transaction>, size_t> get_txs_per_page(const size_t offset) const;
		virtual std::pair<std::vector<c_transaction>, size_t> get_txs_from_block_per_page(const size_t offset, const t_hash_type &block_id) const;
		virtual std::pair<std::vector<std::pair<t_signature_type, t_public_key_type>>, size_t> get_block_signatures_and_pk_miners_per_page(const size_t offset, const t_hash_type &block_id) const;
		c_blockchain_module(c_mediator & mediator, std::unique_ptr<c_blockchain> &&blockchain, std::unique_ptr<c_utxo> &&utxo); //for only tests
		virtual bool block_exists(const t_hash_type & block_id) const;
		virtual t_hash_type get_auth_txid(const t_public_key_type & pk) const;
		virtual c_transaction add_voting_protocol(const std::vector<unsigned char> & voting_protocol, const t_public_key_type & organizer_pk);
		c_transaction get_tx_voting_protocol(const t_hash_type & hash_voting_protocol) const;
		std::vector<t_hash_type> get_hashes_voting_protocols() const;
	protected:
		c_blockchain_module(c_mediator & mediator);
	private:
		void miner_thread_loop();
		/**
		 * @return true when tmp_block updated
		 */
		void update_block_tmp(const c_block & block);
		std::unique_ptr<c_blockchain> m_blockchain;
		std::unique_ptr<c_utxo> m_utxo;
		std::unique_ptr<c_block_verifier> m_block_verifyer;
		std::unique_ptr<c_mempool> m_mempool;
		std::unique_ptr<c_miner> m_miner;
		mutable std::shared_mutex m_blockchain_mutex; // protect all blockchain module operations
		std::thread m_miner_thread;
		std::atomic<bool> m_miner_stop_flag = false;
		std::optional<c_block> m_block_tmp; ///< this block waits for more miners signatures
		void add_verifyed_block_to_blockchain(const c_block& block);
		void broadcast_block(const c_block & block) const;
		t_public_key_type get_my_pk() const;
		void sign_block(c_block & block) const;
		t_signature_type sign_by_main_identity(const t_hash_type & data_to_sign) const;
		std::vector<t_signature_type> get_signatures_per_page(const size_t offset, std::vector<t_signature_type> & block_signatures) const;
		bool m_force_mine = false; // admin ignore blockchain sync and create new block
};

#endif // BLOCKCHAIN_MODULE_HPP
