#ifndef BLOCKCHAIN_MODULE_HPP
#define BLOCKCHAIN_MODULE_HPP

#include "component.hpp"
#include "blockchain.hpp"
#include "block_verifier.hpp"
#include "utxo.hpp"
#include "mempool.hpp"
#include "authorization_level_data.hpp"
#include <shared_mutex>
#include <thread>
#include <tuple>
#include <optional>

class c_blockchain_module : public c_component {
	friend class c_blockchain_module_builder;
	friend std::unique_ptr<c_blockchain_module> std::make_unique<c_blockchain_module>(c_mediator &);
	public:
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
		virtual size_t get_number_of_mempool_transactions() const;
		virtual std::vector<c_transaction> get_mempool_transactions() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_votings() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_active_votings() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_finished_votings() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_finished_votings_for_voter(const t_public_key_type & voter_pk) const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_inactive_votings() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_active_votings_for_voter(const t_public_key_type & voter_pk) const;
		std::tuple<c_blockchain *, std::shared_mutex *, c_utxo *> get_blockchain_ref(); // for simulation only!
		void run() override;
		virtual bool is_pk_organizer(const t_public_key_type & pk) const;
		virtual bool is_pk_issuer(const t_public_key_type & pk) const;
		virtual bool is_pk_voter(const t_public_key_type & pk) const;
		virtual std::vector<t_authorization_data> get_authorization_data(const t_public_key_type & pk) const;
		virtual std::vector<c_transaction> get_voter_auth_tx(const t_public_key_type & voter_pk) const;
		virtual t_hash_type get_hash_personal_data(const t_public_key_type &voter_pk) const;
		virtual uint32_t get_amount_pkh(const t_hash_type &pkh) const;
		/**
		 * @return public key of voting organizer
		 */
		virtual bool check_the_voter_voted(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const;
		virtual t_hash_type get_voter_auth_txid_for_voting(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const;
		virtual t_voting_metadata get_voting_details(const t_hash_type & voting_id) const;
		t_public_key_type get_voting_creator_pk(const t_hash_type & voting_id) const;
		static t_hash_type get_vote_option_hash(const c_transaction & create_voting_tx, const std::vector<unsigned char> & option);
		/**
		 * @brief get_source_tx
		 * @return txid of transaction containing vout with given pkh
		 */
		virtual t_hash_type get_source_txid(const t_hash_type & pkh) const;
		/**
		 * @brief get_all_vote_transactions
		 * Iterate over all transaction and get all vote transactions
		 */
		virtual std::vector<c_transaction> get_all_vote_transactions(const t_hash_type & voting_id) const;
		virtual std::vector<t_hash_type> get_merkle_branch(const t_hash_type & txid) const;
		virtual t_hash_type get_block_id_by_txid(const t_hash_type & txid) const;
		virtual std::vector<t_public_key_type> get_voter_groups(const t_public_key_type & voter_pk) const;
		virtual bool is_blockchain_synchronized() const;
		virtual size_t get_number_of_all_voters() const;
		virtual size_t get_number_of_miners() const;
		virtual size_t get_number_of_all_voters_in_group(const t_public_key_type & organizer_pk) const;
		virtual size_t get_all_added_votes() const;
		virtual size_t get_number_of_transactions() const;
		virtual std::vector<c_block_record> get_last_5_blocks() const;
		virtual std::vector<c_transaction> get_last_5_transactions() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_last_5_votings() const;
		virtual std::vector<c_block_record> get_sorted_blocks(const size_t amount_of_blocks) const;
		virtual std::pair<std::vector<c_block_record>, size_t> get_sorted_blocks_per_page(const size_t offset) const;
		virtual std::vector<c_transaction> get_latest_transactions(const size_t amount_txs) const;
		virtual std::pair<std::vector<c_transaction>, size_t> get_txs_per_page(const size_t offset) const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_latest_votings(const size_t amount_votings) const;
		virtual std::pair<std::vector<std::pair<t_hash_type, t_voting_metadata>>, size_t> get_votings_per_page(const size_t offset) const;
		virtual std::pair<std::vector<c_transaction>, size_t> get_txs_from_block_per_page(const size_t offset, const t_hash_type &block_id) const;
		virtual std::pair<std::vector<std::pair<t_signature_type, t_public_key_type>>, size_t> get_block_signatures_and_pk_miners_per_page(const size_t offset, const t_hash_type &block_id) const;
		virtual std::vector<std::pair<t_hash_type, bool>> finished_or_active_votings(const std::vector<std::pair<t_hash_type, t_voting_metadata>> &votings) const;
		virtual std::vector<std::pair<t_hash_type, double>> get_voter_turnout_from_specific_votes(const std::vector<std::pair<t_hash_type, t_voting_metadata>> &votings) const;
		virtual std::vector<t_hash_type> get_waiting_votings_ids(const std::vector<std::pair<t_hash_type, t_voting_metadata>> &votings) const;
		virtual std::vector<std::pair<t_hash_type, std::unordered_map<std::string, uint32_t>> >get_votings_results_from_specific_votes(const std::vector<std::pair<t_hash_type, t_voting_metadata>> &votings) const;
		virtual std::pair<std::vector<std::pair<t_hash_type, t_voting_metadata>>, size_t> get_all_votings_by_name_or_voting_id_with_number_votings(const size_t offset, const std::string &voting_name_or_id) const;
		virtual double get_voter_turnout_from_vote(const t_hash_type & voting_id) const;
		virtual std::unordered_map<std::string, uint32_t> get_voting_result(const t_hash_type & voting_id) const;
		virtual unsigned char get_voting_status(const t_hash_type &voting_id) const;
		c_blockchain_module(c_mediator & mediator, std::unique_ptr<c_blockchain> &&blockchain, std::unique_ptr<c_utxo> &&utxo); //for only tests
		virtual bool block_exists(const t_hash_type & block_id) const;
		std::vector<t_hash_type> get_txids_of_tx_auth_voter(const t_public_key_type & pk) const;
		void reindex_chainstate();
	protected:
		c_blockchain_module(c_mediator & mediator);
	private:
		void update_block_tmp(const c_block & block);
		std::vector<std::pair<t_hash_type, t_voting_metadata>> get_voting_by_name_or_by_id(const std::string & voting_name_or_id) const;
		std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_voting_by_the_same_name(const std::string & voting_name) const;
		bool is_voting_finished(const t_hash_type & voting_id) const;
		bool is_voting_active(const t_hash_type & voting_id) const;
		std::unique_ptr<c_blockchain> m_blockchain;
		std::unique_ptr<c_utxo> m_utxo;
		std::unique_ptr<c_block_verifier> m_block_verifyer;
		std::unique_ptr<c_mempool> m_mempool;
		mutable std::shared_mutex m_blockchain_mutex; // protect all blockchain module operations
		std::optional<c_block> m_block_tmp; ///< this block waits for more miners signatures
		void add_verifyed_block_to_blockchain(const c_block& block);
		void broadcast_block(const c_block & block) const;
		std::vector<unsigned char> get_co_color(const std::vector<unsigned char> & allmetadata) const;
		bool is_voter_authorized_for_this_group(const std::vector<unsigned char> & co_color, const t_public_key_type & pk) const;
		std::vector<t_signature_type> get_signatures_per_page(const size_t offset, std::vector<t_signature_type> & block_signatures) const;
		bool is_active_or_finished(const t_hash_type & voting_id) const;
		bool is_waiting(const t_hash_type & voting_id) const;
		t_voting_metadata get_voting_metadata_by_voting_id(const t_hash_type & voting_id) const;
};

#endif // BLOCKCHAIN_MODULE_HPP
