#ifndef C_PEER_FINDER_HPP
#define C_PEER_FINDER_HPP

#include "peer_reference.hpp"
#include <filesystem>
#include <memory>
#include <leveldb/db.h>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

struct t_peer_finder_address {
	std::string m_external_address; // i.e. IP address
	unsigned short m_port;
	uint64_t m_timestamp; // last activity
};

class c_peer_finder {
	public:
		c_peer_finder(const std::filesystem::path & datadir_path);
		virtual ~c_peer_finder() = default;
		virtual std::vector<t_peer_finder_address> load_peers();
		/**
		 * @param addres_port <public ip/onion>:<port>
		 */
		void update_peer_activity(const std::string & public_address_port, uint64_t last_activity_time);
		void update_peer_activity(const std::string & public_address_port);
		void update_peer_activity(const c_peer_reference & local_reference);
		void update_peer_activity(const c_peer_reference & local_reference, uint64_t last_activity_time);
		void assign_local_reference_to_external_address(const c_peer_reference & local_reference, const std::string & public_address_port);
		/**
		 * for blacklist peer last activity time == 0
		 */
		void set_peer_blacklist(const std::string & public_address_port);
		bool is_peer_blacklisted(const std::string & public_address_port) const;
		virtual bool is_my_address(const std::string & public_address_port) const;
	private:
		std::unique_ptr<leveldb::DB> m_database; // <public ip/onion>:<port> => timestamp
		std::unordered_map<std::string, std::string> m_local_to_external_map; // "peer_reference string => <public ip/onion>:<port>"
		mutable std::shared_mutex m_local_to_external_map_mtx;
		std::unordered_set<std::string> m_my_addresses; // <public ip/onion>:<port>
};

#endif // C_PEER_FINDER_HPP
