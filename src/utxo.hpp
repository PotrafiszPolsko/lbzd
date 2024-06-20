#ifndef UTXO_HPP
#define UTXO_HPP
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <leveldb/db.h>
#include "block.hpp"
#include "blockchain.hpp"
#include "utils.hpp"

// database struct
// "m" + pkh == miner auth txid
// "v" + pkh == voter auth txid
// "i" + pkh == issuer auth txid
// "o" + pkh == organizer auth txid
// "V" + active votings unique voting id => active voting metadata
// "X" == completed votings
// "W" == waiting voting (not start yet)
// "s" + unique voting key => start voting block height (0 if waiting)
// "a" + pkh => 4 bytes + 32 bytes == amount on adddress saved on 4 bytes integer + txid of source transaction
// "l" => hash of last scanned block
// "c" + hash(voter_pk + CE) => null // if exists then voter voted in this voting

class c_utxo {
	public:
		c_utxo() = default; //only for tests
		c_utxo(const std::filesystem::path & datadir_path);
		virtual ~c_utxo() = default;
		void update(const c_block & block, size_t height);
		uint32_t get_amount_on_pk(const t_public_key_type & pk) const;
		virtual uint32_t get_amount_on_pkh(const t_hash_type & pkh) const;
		bool is_pk_miner(const t_public_key_type & pk) const;
		bool is_pk_organizer(const t_public_key_type & pk) const;
		bool is_pk_issuer(const t_public_key_type & pk) const;
		bool is_pk_voter(const t_public_key_type & pk) const;

		virtual std::vector<t_public_key_type> get_all_miners_public_keys() const;
		/**
		 * @return pair [voting_id, metadata]
		 */
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_votings() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_active_votings() const;
		void update_voting_status(uint32_t current_block_time, size_t current_block_height);
		/**
		 * @return list of colors and parent colors for given pk
		 */
		virtual std::vector<t_public_key_type> get_parent_list_voter(const t_public_key_type & voter_pk, const c_blockchain & blockchain) const;
		std::vector<t_hash_type> get_txids_of_tx_auth_issuer(const t_public_key_type & pk) const;
		std::vector<t_hash_type> get_txids_of_tx_auth_organizer(const t_public_key_type & pk) const;
		virtual std::vector<t_hash_type> get_txids_of_tx_auth_voter(const t_public_key_type & pk) const;
		std::vector<t_hash_type> get_txids_of_tx_auth_miner(const t_public_key_type &pk) const;
		std::vector<t_hash_type> get_auth_txid(const t_public_key_type & pk) const;
		bool has_voter_voting_right(const t_hash_type & voting_id, const t_public_key_type & voter_pk, const c_blockchain & blockchain) const;
		/**
		 * @brief get_number_of_miners
		 * @return number of actual active miners
		 */
		virtual size_t get_number_of_miners() const;
		virtual t_hash_type get_hash_of_data_voter(const t_public_key_type & pk) const;
		/**
		 * @return true if voter not voted in this voting
		 */
		bool check_the_voter_voted(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const;
		/**
		 * @brief get_source_tx
		 * @return txid of transaction containing vout with given pkh
		 */
		t_hash_type get_source_txid(const t_hash_type & pkh) const;
		virtual size_t get_number_of_all_voters() const;
		virtual size_t get_number_voters_in_group(const t_public_key_type & organizer_pk, const c_blockchain & blockchain) const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_finished_votings() const;
		virtual std::vector<std::pair<t_hash_type, t_voting_metadata>> get_all_waiting_votings() const;
		virtual t_voting_metadata get_voting_metadata_by_voting_id(const t_hash_type & voting_id) const;
		virtual unsigned char get_voting_status(const t_hash_type & voting_id) const;
	private:
		t_voting_metadata get_voting_data(const t_hash_type & voting_id, char database_prefix) const;
		void add_pk_miner(const t_public_key_type & pk, const t_hash_type & txid);
		void add_pkh_organizer(const t_hash_type & pkh, const t_hash_type & txid);
		void add_pkh_issuer(const t_hash_type & pkh, const t_hash_type & txid);
		void add_pkh_voter(const t_hash_type & pkh, const t_hash_type & txid);
		void add_voting(const t_hash_type & txid, const std::vector<unsigned char> & metadata);
		void add_hash_of_data_voter(const t_hash_type & hash_data_voter, const t_hash_type & pkh_voter);
		void remove_zero_amounts_pk();
		void write_last_scanned_block_hash(const t_hash_type & block_hash);
		t_hash_type read_last_scanned_block_hash() const;
		std::vector<t_hash_type> get_txids_of_tx_auth(const std::string & db_key) const; //if not found txid return empty vector
		mutable std::unique_ptr<leveldb::DB> m_database;
		void check_voting_metadata_fieds(const std::unordered_multimap<std::string, std::vector<unsigned char>> & metadata_map) const;
		std::vector<std::pair<t_hash_type, t_voting_metadata> > get_voting_base(char database_key_prefix) const;
		void set_voting_start_height(const t_hash_type & voting_id, uint32_t height);
		uint32_t get_voting_start_height(const t_hash_type & voting_id);
		t_voting_metadata metadata_to_struct(std::string_view metadata) const;
		void update_voting_status_waiting_to_active(uint32_t current_block_time, size_t current_block_height);
		void update_voting_status_active_to_finished(size_t current_block_height);
		std::vector<t_public_key_type> get_parent_list(const t_hash_type & auth_txid, const c_blockchain & blockchain) const;
		void set_the_voter_voted(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const;
		const std::string get_db_key_for_mark_voter_voted(const t_public_key_type& voter_pk, const t_hash_type& voting_id) const;
};



#endif // UTXO_HPP
