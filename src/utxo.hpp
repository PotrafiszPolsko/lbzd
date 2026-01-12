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
// "o" + pkh == organizer auth txid
// "V" + hash_voting_protocol
// "l" => hash of last scanned block

class c_utxo {
	public:
		c_utxo() = default; //only for tests
		c_utxo(const std::filesystem::path & datadir_path);
		virtual ~c_utxo() = default;
		void update(const c_block & block);
		virtual bool is_pk_miner(const t_public_key_type & pk) const;
		virtual bool is_pk_organizer(const t_public_key_type & pk) const;

		virtual std::vector<t_public_key_type> get_all_miners_public_keys() const;
		virtual t_hash_type get_auth_txid(const t_public_key_type & pk) const;
		/**
		 * @brief get_number_of_miners
		 * @return number of actual active miners
		 */
		virtual size_t get_number_of_miners() const;
		/**
		 * @brief get_source_tx
		 * @return txid of transaction containing vout with given pkh
		 */
		virtual std::vector<t_hash_type> get_hashes_of_voting_protocols() const;
		virtual t_hash_type get_voting_protocol_txid(const t_hash_type & hash_voting_protocol) const;
		t_hash_type get_txid_of_tx_auth_organizer(const t_public_key_type & pk) const;
	private:
		void add_pk_miner(const t_public_key_type & pk, const t_hash_type & txid);
		void add_pkh_organizer(const t_hash_type & pkh, const t_hash_type & txid);
		void add_hash_voting_protocol(const t_hash_type & hash_voting_protocol, const t_hash_type & txid);
		void write_last_scanned_block_hash(const t_hash_type & block_hash);
		t_hash_type read_last_scanned_block_hash() const;
		t_hash_type get_txid_of_tx_auth(const std::string & db_key) const; //if not found txid return txid fills 0
		t_hash_type get_txid_of_tx_auth_miner(const t_public_key_type &pk) const;
		mutable std::unique_ptr<leveldb::DB> m_database;
};



#endif // UTXO_HPP
