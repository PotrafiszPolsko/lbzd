#ifndef P2P_MODULE_HPP
#define P2P_MODULE_HPP

#include "component.hpp"
#include "p2p_session_manager_tcp.hpp"
#include "p2p_session_manager_tor.hpp"
#include "p2p.pb.h"
#include "port_forwarder.hpp"
#include "peer_finder.hpp"
#include <gtest/gtest.h>

class c_p2p_module : public c_component {
		friend class c_p2p_module_builder;
		friend class c_p2p_module_builder_tests;
		friend std::unique_ptr<c_p2p_module> std::make_unique<c_p2p_module>(c_mediator &);
		FRIEND_TEST(p2p_module, send_proto_message_to_peer_parse_tx);
		FRIEND_TEST(p2p_module, send_proto_message_to_peer_parse_addr);
		FRIEND_TEST(p2p_module, send_proto_message_to_peer_parse_request_getaddr);
	public:
		c_p2p_module(c_mediator & mediator);
		void run() override;
		void read_handler_tcp(const c_peer_reference & endpoint, span<const unsigned char> data);
		virtual void broadcast_transaction(const c_transaction & transaction, bool only_tor = false);
		virtual void broadcast_block(const c_block & block);
		virtual std::vector<std::unique_ptr<c_peer_reference> > get_peers_tcp() const;
		virtual std::vector<std::unique_ptr<c_peer_reference> > get_peers_tor() const;
		virtual void new_identity_tor();
		void new_peer_handler(const c_peer_reference & endpoint);
	private:
		std::unique_ptr<c_p2p_session_manager_tcp> m_session_manager_tcp;
		std::unique_ptr<c_p2p_session_manager_tor> m_session_manager_tor;
		std::unique_ptr<c_port_forwarder> m_port_forwarder;
		std::unique_ptr<c_peer_finder> m_peer_finder;
		std::vector<c_header> m_headers_to_download;
		std::mutex m_headers_to_download_mutex;
		std::chrono::time_point<std::chrono::system_clock> m_time_to_download_headers;
		std::optional<std::pair<std::string, unsigned short>> m_my_public_address_form_commandline;
		static const std::array<std::pair<std::string, unsigned short>, 3> s_seed_nodes;
		void gettx_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void getblock_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void getheaders_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void getmempooltxs_request(const c_peer_reference & endpoint);
		void getaddr_request(const c_peer_reference & endpoint);
		void getmerklebranch_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void getallactivevotingsforvoter_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void getallfinishedvotingsforvoter_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void getamountonpkh_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void gettransaction_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void getauthtxid_request(const proto::request & request_proto, const c_peer_reference & endpoint);
		void parse_proto_request(const proto::request & request, const c_peer_reference & endpoint);
		void parse_proto_headers(const proto::headers & headers_proto, const c_peer_reference & endpoint);
		void parse_proto_block(const proto::block & block_proto, const c_peer_reference & endpoint);
		void parse_proto_addr(const proto::addr & addr_proto);
		void parse_proto_merkle_branch(const proto::merkle_branch & merkle_branch);
		void ask_for_block(const c_header & header, const c_peer_reference & endpoint);
		void ask_for_headers();
		void ask_for_mempool();
		void ask_for_peers(const c_peer_reference & endpoint);
		void start_port_forwarding(unsigned short port);
		void connect_to_saved_peers();
		size_t number_of_connected_peers() const;
		void connect_to_random_seed_node();
		void connect_to_peer(const std::string & ip_str, unsigned short port);
		bool am_i_seed_node() const;
		void send_proto_message_to_peer(const proto::proto_massage & proto_message, const c_peer_reference & endpoint);
		void broadcast_proto_message(const proto::proto_massage & proto_message, const bool only_tor = false);
		/**
		 * @brief broadcast_block broadcast to all peers except @param endpoint
		 */
		void broadcast_block(const c_block & block, const c_peer_reference & endpoint);
		void broadcast_external_ip(const std::string ip, unsigned short port);
		bool block_exists(const t_hash_type & block_id) const;
		void disconnect_peer(const c_peer_reference & endpoint);
};

#endif // P2P_MODULE_HPP
