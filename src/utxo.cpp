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

void c_utxo::update(const c_block & block, size_t height) {
	const auto last_scanned_block_hash = read_last_scanned_block_hash();
	if (block.m_header.m_parent_hash != last_scanned_block_hash) throw std::invalid_argument("bad block order");
	for (const auto & tx : block.m_transaction) {
		try {
			const auto metadata = [&tx](){
				if (tx.m_type == t_transactiontype::another_voting_protocol) // disable parsing
					return std::unordered_multimap<std::string, std::vector<unsigned char>>{};
				else
					return get_metadata_map(tx.m_allmetadata);
			}();
			const auto txid_as_string = container_to_string(tx.m_txid);
			for (const auto & vout : tx.m_vout) {
				std::string amount_as_str;
				const std::string db_key = 'a' + container_to_string(vout.m_pkh);
				auto status = m_database->Get(leveldb::ReadOptions(), db_key, &amount_as_str);
				if (status.IsNotFound()) {
					const auto amount_as_array = get_array_byte(vout.m_amount);
					const auto new_amount_as_str = container_to_string(amount_as_array);
					status = m_database->Put(leveldb::WriteOptions(), db_key, new_amount_as_str + txid_as_string);
					if (!status.ok()) throw std::runtime_error("write amount to db error: " + status.ToString());
				} else if (!status.ok()) {
					throw std::runtime_error("read amount from db error: " + status.ToString());
				} else {
					std::array<unsigned char, 4> amount_as_array;
					std::copy_n(amount_as_str.cbegin(), amount_as_array.size(), amount_as_array.begin());
					uint32_t amount = get_integer<uint32_t>(amount_as_array);
					amount += vout.m_amount;
					amount_as_array = get_array_byte(amount);
					amount_as_str = container_to_string(amount_as_array);
					status = m_database->Put(leveldb::WriteOptions(), db_key, amount_as_str + txid_as_string);
					if (!status.ok()) throw std::runtime_error("write amount to db error: " + status.ToString());
				}
			}
			if (tx.m_type == t_transactiontype::authorize_miner) {
				t_public_key_type miner_pk;
				const auto & miner_pk_as_vector = metadata.find("PK")->second;
				assert(miner_pk.size() == miner_pk_as_vector.size());
				std::copy(miner_pk_as_vector.cbegin(), miner_pk_as_vector.cend(), miner_pk.begin()); // always one miner per tx
				add_pk_miner(miner_pk, tx.m_txid);
			} else if (tx.m_type == t_transactiontype::authorize_organizer) {
				// always one organizer per tx
				const t_hash_type organizer_pkh = tx.m_vout.at(0).m_pkh;
				add_pkh_organizer(organizer_pkh, tx.m_txid);
			} else if (tx.m_type == t_transactiontype::authorize_issuer) {
				const t_hash_type issuer_pkh = tx.m_vout.at(0).m_pkh;
				add_pkh_issuer(issuer_pkh, tx.m_txid);
			} else if (tx.m_type == t_transactiontype::authorize_voter) {
				const t_hash_type voter_pkh = tx.m_vout.at(0).m_pkh;
				add_pkh_voter(voter_pkh, tx.m_txid);
			} else if (tx.m_type == t_transactiontype::create_voting) {
				add_voting(tx.m_txid, tx.m_allmetadata);
			} else if (tx.m_type == t_transactiontype::coin_join) {
				for (const auto & vin : tx.m_vin) {
					if (is_pk_voter(vin.m_pk)) {
						assert(metadata.count("VI") != 0);
						const auto vi_as_vector = metadata.find("VI")->second;
						t_hash_type vi;
						std::copy(vi_as_vector.cbegin(), vi_as_vector.cend(), vi.begin());
						if (is_pk_voter(vin.m_pk)) {
							set_the_voter_voted(vin.m_pk, vi);
						}
						continue; // no remove voters voting right
					}
					const auto pkh = generate_hash(vin.m_pk);
					const auto db_key = 'a' + container_to_string(pkh);
					std::string amount;
					auto status = m_database->Get(leveldb::ReadOptions(), db_key, &amount);
					if (!status.ok()) {
						throw std::runtime_error("read amount from db error: " + status.ToString());
					}
					// no check amount because we always spend all tokens
					status = m_database->Delete(leveldb::WriteOptions(), db_key);
					if (!status.ok()) throw std::runtime_error("delete 0 amount from db error: " + status.ToString());
				}
			} else if (tx.m_type == t_transactiontype::add_secret_vote || tx.m_type == t_transactiontype::add_open_vote) {
				for (const auto & vin : tx.m_vin) {
					const auto pkh = generate_hash(vin.m_pk);
					const auto db_key = 'a' + container_to_string(pkh);
					std::string amount;
					auto status = m_database->Get(leveldb::ReadOptions(), db_key, &amount);
					if (!status.ok()) {
						throw std::runtime_error("read amount from db error: " + status.ToString());
					}
					const auto vi_as_vector = metadata.find("VI")->second;
					t_hash_type vi;
					std::copy(vi_as_vector.cbegin(), vi_as_vector.cend(), vi.begin());
					if (is_pk_voter(vin.m_pk)) {
						set_the_voter_voted(vin.m_pk, vi);
					} else {
						// no check amount because we always spend all tokens
						status = m_database->Delete(leveldb::WriteOptions(), db_key);
						if (!status.ok()) throw std::runtime_error("delete 0 amount from db error: " + status.ToString());
					}
				}
			} else if (tx.m_type == t_transactiontype::another_voting_protocol) {
				LOG(info)<<"added a transaction with voting results from a another protocol";
			} else if (tx.m_type == t_transactiontype::hash_personal_data) {
				const auto & hash_data_voter_with_header = tx.m_allmetadata;
				const auto hash_data_voter = get_metadata_map(hash_data_voter_with_header);
				const auto hash_data_voter_as_vector = hash_data_voter.find("PD")->second;
				t_hash_type hash_data_voter_as_array;
				std::copy(hash_data_voter_as_vector.cbegin(), hash_data_voter_as_vector.cend(), hash_data_voter_as_array.begin());
				add_hash_of_data_voter(hash_data_voter_as_array, tx.m_vout.at(0).m_pkh);
			} else throw std::invalid_argument("not known transaction type");
		} catch (const std::exception & exception) {
			LOG(warning) << "Parse transaction error: " << exception.what();
		}
	}
	write_last_scanned_block_hash(block.m_header.m_actual_hash);
	remove_zero_amounts_pk();
	update_voting_status(block.m_header.m_block_time, height);
}

uint32_t c_utxo::get_amount_on_pk(const t_public_key_type & pk) const {
	const auto pkh = generate_hash(pk);
	return get_amount_on_pkh(pkh);
}

uint32_t c_utxo::get_amount_on_pkh(const t_hash_type &pkh) const {
	const auto db_key = 'a' + container_to_string(pkh);
	std::string amount_as_str;
	auto status = m_database->Get(leveldb::ReadOptions(), db_key, &amount_as_str);
	if (status.IsNotFound()) return 0;
	if (!status.ok()) throw std::runtime_error("get_amount_on_pkh() db error " + status.ToString());
	std::array<unsigned char, 4> amount_as_array;
	std::copy_n(amount_as_str.cbegin(), amount_as_array.size(), amount_as_array.begin());
	const auto amount = get_integer<uint32_t>(amount_as_array);
	return amount;
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

void c_utxo::add_pkh_issuer(const t_hash_type & pkh, const t_hash_type & txid) {
	const std::string pkh_as_str = container_to_string(pkh);
	const std::string db_key = "i" + pkh_as_str;
	const std::string txid_as_string = container_to_string(txid);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, txid_as_string);
	if (!status.ok()) throw std::runtime_error("Add issuer to db error " + status.ToString());
}

void c_utxo::add_pkh_voter(const t_hash_type & pkh, const t_hash_type & txid) {
	const std::string pkh_as_str = container_to_string(pkh);
	const std::string db_key = "v" + pkh_as_str;
	std::string txids;
	const std::string txid_as_string = container_to_string(txid);
	auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txids);
	if (status.IsNotFound()) {
		status = m_database->Put(leveldb::WriteOptions(), db_key, txid_as_string);
		if (!status.ok()) throw std::runtime_error("Add voter to db error " + status.ToString());
	} else if (status.ok()) {
		std::string old_txids;
		status = m_database->Get(leveldb::ReadOptions(), db_key, &old_txids);
		if (!status.ok()) throw std::runtime_error("Get old auth txids from db error " + status.ToString());
		if (old_txids.find(txid_as_string) != std::string::npos) throw std::invalid_argument("Voter already added");
		old_txids += txid_as_string;
		status = m_database->Put(leveldb::WriteOptions(), db_key, old_txids);
	} else throw std::runtime_error("read voter auth txid error: " + status.ToString());
}

void c_utxo::add_voting(const t_hash_type & txid, const std::vector<unsigned char> & metadata) {
	const std::string db_key = 'W' + container_to_string(txid);
	const auto metadata_as_str = container_to_string(metadata);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, metadata_as_str);
	if (!status.ok()) throw std::runtime_error("Add voting to db error: " + status.ToString());
}

void c_utxo::add_hash_of_data_voter(const t_hash_type &hash_data_voter, const t_hash_type &pkh_voter) {
	const std::string db_key = 'H' + container_to_string(pkh_voter);
	const auto hash_data_as_str = container_to_string(hash_data_voter);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, hash_data_as_str);
	if (!status.ok()) throw std::runtime_error("Add hash personal data to db error: " + status.ToString());
}

t_hash_type c_utxo::get_hash_of_data_voter(const t_public_key_type &pk) const {
	const auto & pkh_voter = generate_hash(pk);
	const std::string db_key = 'H' + container_to_string(pkh_voter);
	std::string hash_as_str;
	auto status = m_database->Get(leveldb::ReadOptions(), db_key, &hash_as_str);
	if (!status.ok()) throw std::runtime_error("Get hash personal data to db error: " + status.ToString());
	const auto hash_as_array = transform_string_to_array<hash_size>(hash_as_str);
	return hash_as_array;
}

void c_utxo::remove_zero_amounts_pk() {
	std::vector<std::string> zero_amount_db_key;
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice("a")); it->Valid(); it->Next()) {
		const auto status = it->status();
		if (!status.ok()) throw std::runtime_error("iterating db error: " + status.ToString());
		const auto db_key = it->key().ToString();
		if (db_key.front() != 'a') break;
		const auto amount_as_str = it->value().ToString();
		std::array<unsigned char, 4> amount_as_array;
		std::copy_n(amount_as_str.cbegin(), amount_as_array.size(), amount_as_array.begin());
		const uint32_t amount = get_integer<uint32_t>(amount_as_array);
		if (amount == 0) {
			zero_amount_db_key.push_back(db_key);
		}
	}
	for (const auto & db_key : zero_amount_db_key) {
		auto status = m_database->Delete(leveldb::WriteOptions(), db_key);
		if (!status.ok()) throw std::runtime_error("delete record from db error" + status.ToString());
	}
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

std::vector<t_hash_type> c_utxo::get_txids_of_tx_auth(const std::string & db_key) const {
	std::string txid_as_str;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txid_as_str);
	if (status.IsNotFound()) return {};
	if (!status.ok()) throw std::runtime_error("read txid from db error: " + status.ToString());
	const auto number_of_txids = txid_as_str.size()/hash_size;
	std::vector<t_hash_type> txids(number_of_txids);
	for(size_t i=0; i<number_of_txids; i++) std::copy_n(txid_as_str.cbegin()+i*hash_size, hash_size, txids.at(i).begin());
	return txids;
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

bool c_utxo::is_pk_issuer(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "i" + container_to_string(pkh);
	std::string txid;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txid);
	if (status.IsNotFound()) return false;
	else if (status.ok()) return true;
	else throw std::runtime_error("read issuer pk from db error: " + status.ToString());
}

bool c_utxo::is_pk_voter(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "v" + container_to_string(pkh);
	std::string txid;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txid);
	if (status.IsNotFound()) return false;
	else if (status.ok()) return true;
	else throw std::runtime_error("read voter pk from db error: " + status.ToString());
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

void c_utxo::check_voting_metadata_fieds(const std::unordered_multimap<std::string, std::vector<unsigned char>> & metadata_map) const {
	if (metadata_map.count("AL") != 1) throw std::runtime_error("Not found AL metadata field");
	if (metadata_map.count("VN") != 1) throw std::runtime_error("Not found VN metadata field");
	if (metadata_map.count("BE") != 1) throw std::runtime_error("Not found BE metadata field");
	if (metadata_map.count("NC") != 1) throw std::runtime_error("Not found NC metadata field");
	if (metadata_map.count("ST") != 1) throw std::runtime_error("Not found ST metadata field");
	if (metadata_map.count("QS") != 1) throw std::runtime_error("Not found QS metadata fields");
	if (metadata_map.count("OP") < 2) throw std::runtime_error("Not found OP metadata fields");
	if (metadata_map.count("VT") != 1) throw std::runtime_error("Not found VT metadata fields");
	if (metadata_map.count("NO") != 1) throw std::runtime_error("Not found NO metadata fields");
}


t_voting_metadata c_utxo::metadata_to_struct(std::string_view metadata) const {
	const auto metadata_map = get_metadata_map(container_to_vector_of_uchars(metadata));
	check_voting_metadata_fieds(metadata_map);
	t_voting_metadata voting;
	voting.m_authorization_level = get_integer<uint32_t>(metadata_map.find("AL")->second);
	voting.m_name = container_to_string(metadata_map.find("VN")->second);
	voting.m_question = container_to_string(metadata_map.find("QS")->second);
	voting.m_number_of_blocks_to_the_end = get_integer<uint32_t>(metadata_map.find("BE")->second);
	voting.m_number_of_choice = get_integer<uint16_t>(metadata_map.find("NC")->second);
	voting.m_start_timepoint = get_integer<uint32_t>(metadata_map.find("ST")->second);
	voting.m_voting_type = get_integer<uint8_t>(metadata_map.find("VT")->second);
	const auto op_range = metadata_map.equal_range("OP");
	for (auto it = op_range.first; it != op_range.second; ++it)
		voting.m_options.emplace_back(container_to_string(it->second));

	return voting;
}

void c_utxo::update_voting_status_waiting_to_active(const uint32_t current_block_time, const size_t current_block_height) {
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	// iterate over waiting votings
	for (it->Seek(leveldb::Slice("W")); it->Valid(); it->Next()) {
		const auto db_key = it->key().ToString();
		if (db_key.size() != (1 + hash_size)) continue;
		if (db_key.front() != 'W') break;
		const auto metadata = it->value().ToString();
		const auto voting_metadata = metadata_to_struct(metadata);
		// set voting active
		if (current_block_time >= voting_metadata.m_start_timepoint) {
			t_hash_type voting_id;
			std::copy(db_key.cbegin()+1, db_key.cend(), voting_id.begin());
			set_voting_start_height(voting_id, current_block_height);
			const std::string new_db_key = "V" + container_to_string(voting_id);
			auto status = m_database->Put(leveldb::WriteOptions(), new_db_key, metadata);
			if (!status.ok()) throw std::runtime_error("Add active voting to db error: " + status.ToString());
			status = m_database->Delete(leveldb::WriteOptions(), db_key);
			if (!status.ok()) throw std::runtime_error("Remove waiting voting db error: " + status.ToString());	
		}
	}
}

void c_utxo::update_voting_status_active_to_finished(const size_t current_block_height) {
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	// iterate over active votings
	for (it->Seek(leveldb::Slice("V")); it->Valid(); it->Next()) {
		const auto db_key = it->key().ToString();
		if (db_key.size() != (1 + hash_size)) continue;
		if (db_key.front() != 'V') break;
		const auto metadata = it->value().ToString();
		const auto voting_metadata = metadata_to_struct(metadata);
		t_hash_type voting_id;
		assert(voting_id.size()+1 == db_key.size());
		std::copy(std::next(db_key.cbegin() ,1), db_key.cend(), voting_id.begin());
		const auto end_block_height = get_voting_start_height(voting_id) + voting_metadata.m_number_of_blocks_to_the_end;
		// set voting finished
		if (current_block_height == end_block_height) {
			const std::string new_db_key = "X" + container_to_string(voting_id);
			auto status = m_database->Put(leveldb::WriteOptions(), new_db_key, metadata);
			if (!status.ok()) throw std::runtime_error("Add active voting to db error: " + status.ToString());
			status = m_database->Delete(leveldb::WriteOptions(), db_key);
			if (!status.ok()) throw std::runtime_error("Remove waiting voting db error: " + status.ToString());	
		}
	}
}

t_voting_metadata c_utxo::get_voting_data(const t_hash_type & voting_id, const char database_prefix) const {
	const std::string db_key = database_prefix + container_to_string(voting_id);
	std::string metadata;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &metadata);
	if (!status.ok()) throw std::runtime_error("read voting from db error: " + status.ToString());
	t_voting_metadata voting = metadata_to_struct(metadata);
	return voting;
}

std::vector<std::pair<t_hash_type, t_voting_metadata>> c_utxo::get_voting_base(const char database_key_prefix) const {
	std::vector<std::pair<t_hash_type, t_voting_metadata>> voting_vec;
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice(std::string(1, database_key_prefix))); it->Valid(); it->Next()) {
		const auto db_key = it->key().ToString();
		// db_key.size() == prefix + voting_id
		if (db_key.size() != (1 + hash_size)) continue;
		if (db_key.front() != database_key_prefix) break;
		const std::string voting_id_str(db_key.cbegin() + 1, db_key.cend());
		const auto voting_id = transform_string_to_array<hash_size>(voting_id_str);
		auto voting_attribute = get_voting_data(voting_id, database_key_prefix);
		voting_vec.emplace_back(voting_id, voting_attribute);
	}
	return voting_vec;
}

std::vector<std::pair<t_hash_type, t_voting_metadata>> c_utxo::get_all_active_votings() const {
	return get_voting_base('V');
}

 std::vector<std::pair<t_hash_type, t_voting_metadata>> c_utxo::get_all_finished_votings() const {
	return get_voting_base('X');
}
std::vector<std::pair<t_hash_type, t_voting_metadata>>c_utxo::get_all_waiting_votings() const {
	return get_voting_base('W');
}

t_voting_metadata c_utxo::get_voting_metadata_by_voting_id(const t_hash_type &voting_id) const {
	const std::string container_string = container_to_string(voting_id);
	const std::string db_key_V = 'V' + container_string;
	const std::string db_key_X = 'X' + container_string;
	const std::string db_key_W = 'W' + container_string;
	std::string metadata;
	auto status = m_database->Get(leveldb::ReadOptions(), db_key_V, &metadata);
	if (!status.ok()) status = m_database->Get(leveldb::ReadOptions(), db_key_X, &metadata);
	if (!status.ok()) status = m_database->Get(leveldb::ReadOptions(), db_key_W, &metadata);
	if (status.ok()) return metadata_to_struct(metadata);
	t_voting_metadata voting_metadata;
	voting_metadata.m_authorization_level = 0;
	voting_metadata.m_name.clear();
	voting_metadata.m_number_of_blocks_to_the_end = 0;
	voting_metadata.m_number_of_choice = 0;
	voting_metadata.m_options.clear();
	voting_metadata.m_question.clear();
	voting_metadata.m_start_timepoint = 0;
	voting_metadata.m_voting_type = 0;
	return voting_metadata;
}

unsigned char c_utxo::get_voting_status(const t_hash_type &voting_id) const {
	const std::string container_string = container_to_string(voting_id);
	const std::string db_key_V = 'V' + container_string;
	const std::string db_key_X = 'X' + container_string;
	const std::string db_key_W = 'W' + container_string;
	std::string db_key;
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice(db_key_V)); it->Valid(); it->Next()) {
		db_key = it->key().ToString();
		if(db_key == db_key_V) return 'V';
	}
	for (it->Seek(leveldb::Slice(db_key_X)); it->Valid(); it->Next()) {
		db_key = it->key().ToString();
		if(db_key == db_key_X) return 'X';
	}
	for (it->Seek(leveldb::Slice(db_key_W)); it->Valid(); it->Next()) {
		db_key = it->key().ToString();
		if(db_key == db_key_W) return 'W';
	}
	if(db_key != db_key_W && db_key != db_key_X && db_key != db_key_V) throw std::runtime_error("There is no voting id");
	return ' ';
}

void c_utxo::set_voting_start_height(const t_hash_type & voting_id, uint32_t height) {
	const std::string voting_id_as_str = container_to_string(voting_id);
	const std::string db_key = "s" + voting_id_as_str;
	const auto height_as_array = get_array_byte(height);
	const auto height_as_string = container_to_string(height_as_array);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, height_as_string);
	if (!status.ok()) throw std::runtime_error("Save voting start height to db error " + status.ToString());
}

uint32_t c_utxo::get_voting_start_height(const t_hash_type & voting_id) {
	const std::string db_key = "s" + container_to_string(voting_id);
	std::string height_as_str;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &height_as_str);
	if (!status.ok()) throw std::runtime_error("Read voting start height from db error: " + status.ToString());
	const auto height_as_array = transform_string_to_array<4>(height_as_str);
	uint32_t height = get_integer<uint32_t>(height_as_array);
	return height;
}

std::vector<std::pair<t_hash_type, t_voting_metadata>> c_utxo::get_all_votings() const {
	std::vector<std::pair<t_hash_type, t_voting_metadata>> all_votings;
	const auto all_active_votings = get_all_active_votings();
	all_votings.insert(all_votings.begin(), all_active_votings.cbegin(), all_active_votings.cend());
	const auto all_finished_votings = get_all_finished_votings();
	all_votings.insert(all_votings.begin(), all_finished_votings.cbegin(), all_finished_votings.cend());
	const auto all_waiting_votings = get_all_waiting_votings();
	all_votings.insert(all_votings.begin(), all_waiting_votings.cbegin(), all_waiting_votings.cend());
	return all_votings;
}

void c_utxo::update_voting_status(const uint32_t current_block_time, const size_t current_block_height) {
	update_voting_status_waiting_to_active(current_block_time, current_block_height);
	update_voting_status_active_to_finished(current_block_height);
}

std::vector<t_public_key_type> c_utxo::get_parent_list(const t_hash_type & auth_txid, const c_blockchain & blockchain) const {
	auto current_txid = auth_txid;
	std::vector<t_hash_type> parent_list;
	while (true) {
		const auto auth_tx = blockchain.get_transaction(current_txid);
		const auto metadata_map = get_metadata_map(auth_tx.m_allmetadata);
		if (metadata_map.count("CO") != 1) throw std::runtime_error("Not found CO field in auth tx metadata");
		const auto organizer_pk_as_vector = metadata_map.find("CO")->second;
		t_public_key_type organizer_pk;
		std::copy(organizer_pk_as_vector.cbegin(), organizer_pk_as_vector.cend(), organizer_pk.begin());
		const auto organizer_auth_txids = get_txids_of_tx_auth_organizer(organizer_pk);
		for(const auto &organizer_auth_txid:organizer_auth_txids) {
			if (organizer_auth_txid == current_txid) return parent_list;
			parent_list.emplace_back(organizer_pk);
			current_txid = organizer_auth_txid;
		}
	}
	return parent_list;
}

bool c_utxo::check_the_voter_voted(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const {
	if (!is_pk_voter(voter_pk))
		throw std::invalid_argument("Given pk is not voter");
	const auto db_key = get_db_key_for_mark_voter_voted(voter_pk, voting_id);
	std::string input_strng; // should be empty after reading
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &input_strng);
	if (status.IsNotFound()) return false;
	else if (!status.ok()) throw std::runtime_error("Check voter voted error: " + status.ToString());
	else return true;
}

t_hash_type c_utxo::get_source_txid(const t_hash_type & pkh) const {
	const std::string db_key = 'a' + container_to_string(pkh);
	std::string amount_and_txid;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &amount_and_txid);
	if (!status.ok()) {
		throw std::runtime_error("read amount from db error: " + status.ToString());
	}
	if (amount_and_txid.size() != (4 + hash_size)) throw std::runtime_error("Bad db value");
	std::string txid_as_str(amount_and_txid.data() + 4, hash_size);
	t_hash_type txid = transform_string_to_array<hash_size>(txid_as_str);
	return txid;
}

size_t c_utxo::get_number_of_all_voters() const {
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	size_t counter = 0;
	for (it->Seek(leveldb::Slice("v")); it->Valid(); it->Next()) {
		auto db_key = it->key().ToString();
		if (db_key.front() != 'v') break;
		counter++;
	}
	return counter;
}

const std::string c_utxo::get_db_key_for_mark_voter_voted(const t_public_key_type& voter_pk, const t_hash_type& voting_id) const {
	std::vector<unsigned char> hash_input;
	std::copy(voter_pk.cbegin(), voter_pk.cend(), std::back_inserter(hash_input));
	std::copy(voting_id.cbegin(), voting_id.cend(), std::back_inserter(hash_input));
	const std::string db_key = "c" + container_to_string(generate_hash(hash_input));
	return db_key;
}

void c_utxo::set_the_voter_voted(const t_public_key_type & voter_pk, const t_hash_type & voting_id) const {
	if (!is_pk_voter(voter_pk)) 
		throw std::invalid_argument("Given pk is not voter");
	const auto db_key = get_db_key_for_mark_voter_voted(voter_pk, voting_id);
	const auto status = m_database->Put(leveldb::WriteOptions(), db_key, "");
	if (!status.ok()) throw std::runtime_error("mark voter voted to db error: " + status.ToString());
}

std::vector<t_public_key_type> c_utxo::get_parent_list_voter(const t_public_key_type & voter_pk, const c_blockchain & blockchain) const {
	if (!is_pk_voter(voter_pk)) throw std::invalid_argument("not voter pk");
	const auto pkh = generate_hash(voter_pk);
	std::string db_key = "v" + container_to_string(pkh);
	std::string auth_txids_as_string;
	const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &auth_txids_as_string);
	if (!status.ok()) throw std::runtime_error("read voter auth txids from db error: " + status.ToString());
	if ((auth_txids_as_string.size() % hash_size) != 0) throw std::runtime_error("Bad auth_txids size");
	const size_t number_of_txids = auth_txids_as_string.size() / hash_size;
	auto it = auth_txids_as_string.cbegin();
	std::vector<t_hash_type> auth_txids;
	for (size_t i = 0; i < number_of_txids; i++) {
		t_hash_type txid;
		std::copy(it, std::next(it, hash_size), txid.begin());
		std::advance(it, hash_size);
		auth_txids.emplace_back(std::move(txid));
	}
	
	std::vector<t_hash_type> parent_list;
	for (const auto & auth_txid : auth_txids) {
		auto list = get_parent_list(auth_txid, blockchain);
		parent_list.insert(parent_list.cend(), list.cbegin(), list.cend());
	}
	return parent_list;
}

std::vector<t_hash_type> c_utxo::get_txids_of_tx_auth_issuer(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "i" + container_to_string(pkh);
	return get_txids_of_tx_auth(db_key);
}

std::vector<t_hash_type> c_utxo::get_txids_of_tx_auth_organizer(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "o" + container_to_string(pkh);
	return get_txids_of_tx_auth(db_key);
}

std::vector<t_hash_type> c_utxo::get_txids_of_tx_auth_voter(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "v" + container_to_string(pkh);
	return get_txids_of_tx_auth(db_key);
}

std::vector<t_hash_type> c_utxo::get_txids_of_tx_auth_miner(const t_public_key_type &pk) const {
	const auto pkh = generate_hash(pk);
	const std::string db_key = "m" + container_to_string(pkh);
	return get_txids_of_tx_auth(db_key);
}

std::vector<t_hash_type> c_utxo::get_auth_txid(const t_public_key_type &pk) const {
	std::vector<t_hash_type> txids = get_txids_of_tx_auth_voter(pk);
	if(txids.empty()) txids = get_txids_of_tx_auth_issuer(pk);
	if(txids.empty()) txids = get_txids_of_tx_auth_organizer(pk);
	if(txids.empty()) txids = get_txids_of_tx_auth_miner(pk);
	return txids;
}

size_t c_utxo::get_number_voters_in_group(const t_public_key_type & organizer_pk, const c_blockchain & blockchain) const {
	size_t counter = 0;
	std::unique_ptr<leveldb::Iterator> it(m_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice("v")); it->Valid(); it->Next()) {
		auto db_key = it->key().ToString();
		if (db_key.front() != 'v') break;
		std::string txids_as_str;
		const auto status = m_database->Get(leveldb::ReadOptions(), db_key, &txids_as_str);
		if(!status.ok()) break;
		for(size_t i=0; i<txids_as_str.size()/hash_size; i++) {
			const std::string txid_str = txids_as_str.substr(hash_size*i, hash_size);
			const auto txid = transform_string_to_array<hash_size>(txid_str);
			const auto tx = blockchain.get_transaction(txid);
			const auto metadata_map = get_metadata_map(tx.m_allmetadata);
			if (metadata_map.count("CO") != 1) throw std::runtime_error("Not found CO field in authorization tx metadata");
			const auto organizer_pk_as_vector = metadata_map.find("CO")->second;
			t_public_key_type organizer_pk_from_database;
			std::copy(organizer_pk_as_vector.cbegin(), organizer_pk_as_vector.cend(), organizer_pk_from_database.begin());
			if(organizer_pk_from_database == organizer_pk) counter++;
		}
	}
	return counter;
}

bool c_utxo::has_voter_voting_right(const t_hash_type & voting_id, const t_public_key_type & voter_pk, const c_blockchain & blockchain) const {
	const auto parent_list = get_parent_list_voter(voter_pk, blockchain);
	const auto create_voting_tx = blockchain.get_transaction(voting_id);
	if (create_voting_tx.m_vin.size() != 1) throw std::runtime_error("invald create voting transaction");
	const auto & voting_creator_pk = create_voting_tx.m_vin.front().m_pk; // should be always 1 vin
	if (std::find(parent_list.cbegin(), parent_list.cend(), voting_creator_pk) == parent_list.cend()) return false;
	return true;
}

size_t c_utxo::get_number_of_miners() const {
	const auto all_miners_public_keys = get_all_miners_public_keys();
	return all_miners_public_keys.size() - n_blockchainparams::admins_sys_pub_keys.size();
}
