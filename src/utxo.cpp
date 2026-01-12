#include <algorithm>
#include <stdexcept>
#include "logger.hpp"
#include "serialization_utils.hpp"
#include "utxo.hpp"
#include "utils.hpp"
#include "params.hpp"

c_utxo::c_utxo(const std::filesystem::path & datadir_path) {
	const std::filesystem::path chainstate_path = datadir_path/"chainstate";
	if(std::filesystem::create_directories(chainstate_path)) {
		LOG(info) << "Created datadir: " << chainstate_path;
	}
	// open db
	leveldb::Options options;
	options.create_if_missing = true;
	leveldb::DB * db {nullptr};
	const auto status = leveldb::DB::Open(options, chainstate_path.string(), &db);
	m_database.reset(db);
	if (!status.ok()) throw std::runtime_error("Open blocks db error " + status.ToString());
}

void c_utxo::update(const c_block & block) {
	const auto last_scanned_block_hash = read_last_scanned_block_hash();
	if (block.m_header.m_parent_hash != last_scanned_block_hash) throw std::invalid_argument("bad block order");
	for (const auto & tx : block.m_transaction) {
		try {
			if (tx.m_type == t_transactiontype::another_voting_protocol) {
				auto voting_protocol = tx.m_allmetadata;
				t_hash_type hash_of_voting_protocol;
				crypto_generichash(hash_of_voting_protocol.data(), hash_of_voting_protocol.size(),
								   reinterpret_cast<unsigned char*>(voting_protocol.data()), voting_protocol.size(),
								   nullptr, 0);
				add_hash_voting_protocol(hash_of_voting_protocol, tx.m_txid);
			} else if (tx.m_type == t_transactiontype::authorize_miner) {
				t_public_key_type miner_pk;
				const auto & miner_pk_as_vector = tx.m_allmetadata;
				assert(miner_pk.size() == miner_pk_as_vector.size());
				std::copy(miner_pk_as_vector.cbegin(), miner_pk_as_vector.cend(), miner_pk.begin());
				add_pk_miner(miner_pk, tx.m_txid);
			} else if (tx.m_type == t_transactiontype::authorize_organizer) {
				// always one organizer per tx
				const t_hash_type organizer_pkh = tx.m_vout.at(0).m_pkh;
				add_pkh_organizer(organizer_pkh, tx.m_txid);
	
			} else throw std::invalid_argument("not known transaction type");
		} catch (const std::exception & exception) {
			LOG(warning) << "Parse transaction error: " << exception.what();
		}
	}
	write_last_scanned_block_hash(block.m_header.m_actual_hash);
}

void c_utxo::add_pk_miner(const t_public_key_type & pk, const t_hash_type & txid) {
	const std::string pk_as_str = container_to_string(pk);
	const std::string db_key = "m" + pk_as_str;
	const std::string txid_as_string = container_to_string(txid);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, txid_as_string);
	if (!status.ok()) throw std::runtime_error("Add miner to db error " + status.ToString());
}

void c_utxo::add_pkh_organizer(const t_hash_type & pkh, const t_hash_type & txid) {
	const std::string pkh_as_str = container_to_string(pkh);
	const std::string db_key = "o" + pkh_as_str;
	const std::string txid_as_string = container_to_string(txid);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, txid_as_string);
	if (!status.ok()) throw std::runtime_error("Add organizer to db error " + status.ToString());
}

void c_utxo::add_hash_voting_protocol(const t_hash_type &hash_voting_protocol, const t_hash_type &txid) {
	const std::string hash_voting_protocol_as_str = container_to_string(hash_voting_protocol);
	const std::string db_key = "V" + hash_voting_protocol_as_str;
	const std::string txid_as_string = container_to_string(txid);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, txid_as_string);
	if (!status.ok()) throw std::runtime_error("Add hash of voting protocol to db error " + status.ToString());
}

void c_utxo::write_last_scanned_block_hash(const t_hash_type & block_hash) {
	const auto block_hash_as_str = container_to_string(block_hash);
	const auto status = m_database->Put(leveldb::WriteOptions(), "l", block_hash_as_str);
	if (!status.ok()) throw std::runtime_error("write last scanned block hash to db error" + status.ToString());
}

t_hash_type c_utxo::read_last_scanned_block_hash() const {
	std::string block_hash_as_str;
	const auto status = m_database->Get(leveldb::ReadOptions(), "l", &block_hash_as_str);
	t_hash_type block_hash;
	if (status.IsNotFound()) {
		block_hash.fill(0x00);
		return block_hash;
	} else if (!status.ok()) throw std::runtime_error("read last scanned block hash from db error" + status.ToString());
	std::copy(block_hash_as_str.cbegin(), block_hash_as_str.cend(), block_hash.begin());
	return block_hash;
}

t_hash_type c_utxo::get_txid_of_tx_auth(const std::string & db_key) const {
	std::string txid_as_str;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txid_as_str);
	t_hash_type txid;
	if(status.IsNotFound()) {
		txid.fill(0x00);
		return txid;
	}
	if (!status.ok()) throw std::runtime_error("read txid from db error: " + status.ToString());
	std::copy(txid_as_str.cbegin(), txid_as_str.cend(), txid.begin());
	return txid;
}

bool c_utxo::is_pk_miner(const t_public_key_type & pk) const {
	const std::string db_key = "m" + container_to_string(pk);
	std::string txid;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txid);
	if (status.IsNotFound()) return false;
	else if (status.ok()) return true;
	else throw std::runtime_error("read miner pk from db error: " + status.ToString());

}

bool c_utxo::is_pk_organizer(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "o" + container_to_string(pkh);
	std::string txid;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txid);
	if (status.IsNotFound()) return false;
	else if (status.ok()) return true;
	else throw std::runtime_error("read organizer pk from db error: " + status.ToString());
}

std::vector<t_public_key_type> c_utxo::get_all_miners_public_keys() const {
	std::vector<t_public_key_type> miners_addresses;
	std::copy(n_blockchainparams::admins_sys_pub_keys.cbegin(), n_blockchainparams::admins_sys_pub_keys.cend(), std::back_inserter(miners_addresses)); // adminsys can be miner
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice("m")); it->Valid(); it->Next()) {
		// db key = 'm' + miner pk
		auto db_key = it->key().ToString();
		if (db_key.front() != 'm') break;
		db_key.erase(db_key.begin()); // remove 'm'
		t_public_key_type miner_pk;
		std::copy(db_key.cbegin(), db_key.cend(), miner_pk.begin());
		miners_addresses.push_back(miner_pk);
	}
	return miners_addresses;
}

std::vector<t_hash_type> c_utxo::get_hashes_of_voting_protocols() const {
	std::vector<t_hash_type> hashes_of_voting_protocols;
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice(std::string(1, 'V'))); it->Valid(); it->Next()) {
		const auto db_key = it->key().ToString();
		if (db_key.size() != (1 + hash_size)) continue;
		if (db_key.front() != 'V') break;
		const std::string hash_voting_protocol_str(db_key.cbegin() + 1, db_key.cend());
		const auto hash_voting_protocol = transform_string_to_array<hash_size>(hash_voting_protocol_str);
		hashes_of_voting_protocols.emplace_back(hash_voting_protocol);
	}
	return hashes_of_voting_protocols;
}

t_hash_type c_utxo::get_voting_protocol_txid(const t_hash_type &hash_voting_protocol) const {
	const std::string db_key = 'V' + container_to_string(hash_voting_protocol);
	std::string txid_as_str;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txid_as_str);
	if (!status.ok()) throw std::runtime_error("read amount from db error: " + status.ToString());
	t_hash_type txid;
	std::copy(txid_as_str.cbegin(), txid_as_str.cend(), txid.begin());
	return txid;
}

t_hash_type c_utxo::get_txid_of_tx_auth_organizer(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "o" + container_to_string(pkh);
	return get_txid_of_tx_auth(db_key);
}

t_hash_type c_utxo::get_txid_of_tx_auth_miner(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "m" + container_to_string(pkh);
	return get_txid_of_tx_auth(db_key);
}

t_hash_type c_utxo::get_auth_txid(const t_public_key_type &pk) const {
	t_hash_type txid = get_txid_of_tx_auth_organizer(pk);
	t_hash_type txid_tmp;
	txid_tmp.fill(0x00);
	if(txid!=txid_tmp) return txid;
	else txid = get_txid_of_tx_auth_miner(pk);
	if(txid!=txid_tmp && !n_blockchainparams::is_pk_adminsys(pk)) return txid;
	else if(txid==txid_tmp && n_blockchainparams::is_pk_adminsys(pk)) return txid;
	else throw std::invalid_argument("This pk is not authorized");
}

size_t c_utxo::get_number_of_miners() const {
	const auto all_miners_public_keys = get_all_miners_public_keys();
	return all_miners_public_keys.size() - n_blockchainparams::admins_sys_pub_keys.size();
}
