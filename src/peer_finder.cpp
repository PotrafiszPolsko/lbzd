#include "peer_finder.hpp"
#include "logger.hpp"
#include "utils.hpp"

c_peer_finder::c_peer_finder(const std::filesystem::path & datadir_path) {
	const auto db_dir_path = datadir_path/"peers";
	if(std::filesystem::create_directories(db_dir_path)) {
		LOG(info) << "Created datadir tree for peers db: " << db_dir_path;
	}
	leveldb::Options options;
	options.create_if_missing = true;
	leveldb::DB * db {nullptr};
	const auto status = leveldb::DB::Open(options, db_dir_path.string(), &db);
	m_database.reset(db);
	if (!status.ok()) throw std::runtime_error("Open peers db error " + status.ToString());
}

std::vector<t_peer_finder_address> c_peer_finder::load_peers() {
	std::vector<t_peer_finder_address> peer_list;
	leveldb::Iterator* it = m_database->NewIterator(leveldb::ReadOptions());
	for (it->SeekToFirst(); it->Valid(); it->Next()) {
		t_peer_finder_address peer_finder_address;
		const auto public_address_port = it->key().ToString(); // <public ip/onion>:<port>
		const auto colon_pos = public_address_port.find_last_of(':');
		peer_finder_address.m_external_address = public_address_port.substr(0, colon_pos);
		const auto port_str = public_address_port.substr(colon_pos + 1);
		peer_finder_address.m_port = static_cast<unsigned short>(std::stoul(port_str));
		const auto timestamp_as_str = it->value().ToString();
		peer_finder_address.m_timestamp = std::stoul(timestamp_as_str);
		peer_list.emplace_back(std::move(peer_finder_address));
	}
	return peer_list;
}

void c_peer_finder::update_peer_activity(const std::string & public_address_port, uint64_t last_activity_time) {
	if (public_address_port.find(':') == std::string::npos) throw std::invalid_argument("No ':' in address");
	if (is_my_address(public_address_port)) return;
	const auto timestamp_as_str = std::to_string(last_activity_time);
	const auto status = m_database->Put(leveldb::WriteOptions(), public_address_port, timestamp_as_str);
	if (!status.ok()) throw std::runtime_error("write peer activity to db error: " + status.ToString());
}

void c_peer_finder::update_peer_activity(const std::string & public_address_port) {
	if (is_my_address(public_address_port)) return;
	const auto last_activity_time = get_unix_time();
	update_peer_activity(public_address_port, last_activity_time);
}

void c_peer_finder::update_peer_activity(const c_peer_reference & local_reference) {
	const auto last_activity_time = get_unix_time();
	update_peer_activity(local_reference, last_activity_time);
}

void c_peer_finder::update_peer_activity(const c_peer_reference & local_reference, uint64_t last_activity_time) {
	LOG(debug) << "update peer activity " << local_reference.to_string();
	const auto local_reference_as_str = local_reference.to_string();
	std::shared_lock<std::shared_mutex> lock(m_local_to_external_map_mtx);
	if (m_local_to_external_map.count(local_reference_as_str) == 0) return; // not known peer external address
	update_peer_activity(m_local_to_external_map.at(local_reference_as_str), last_activity_time);
}

void c_peer_finder::assign_local_reference_to_external_address(const c_peer_reference & local_reference, const std::string & public_address_port) {
	if (is_my_address(public_address_port)) return;
	if (public_address_port.find(':') == std::string::npos) throw std::invalid_argument("No ':' in address");
	std::lock_guard<std::shared_mutex> lock(m_local_to_external_map_mtx);
	m_local_to_external_map.emplace(local_reference.to_string(), public_address_port);
}

void c_peer_finder::set_peer_blacklist(const std::string & public_address_port) {
	update_peer_activity(public_address_port, 0);
}

bool c_peer_finder::is_peer_blacklisted(const std::string & public_address_port) const {
	std::string timestamp_as_string;
	const auto status = m_database->Get(leveldb::ReadOptions(), public_address_port, &timestamp_as_string);
	if (status.IsNotFound()) return false;
	else if (!status.ok()) throw std::runtime_error("read peer activity from db error: " + status.ToString());
	const uint64_t timestamp = std::stoul(timestamp_as_string);
	return (timestamp == 0);
}

bool c_peer_finder::is_my_address(const std::string & public_address_port) const {
	std::shared_lock<std::shared_mutex> lock(m_local_to_external_map_mtx);
	return (m_my_addresses.count(public_address_port) == 1);
}
