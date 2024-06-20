#ifndef C_P2P_SESSION_MANAGER_HPP
#define C_P2P_SESSION_MANAGER_HPP

#include "peer_reference.hpp"
#include "session.hpp"
#include "p2p_handler_types.hpp"
#include <shared_mutex>

// base class
class c_p2p_session_manager {
	public:
		c_p2p_session_manager(read_handler read_handler, new_peer_handler new_peer_handler, boost::asio::ip::tcp::endpoint listen_endpoint);
		virtual ~c_p2p_session_manager();
		void add_peer(const c_peer_reference & peer_info);
		void async_read(const c_peer_reference & peer_info, read_handler handler);
		void send_to_peer(const c_peer_reference & peer_info, const std::string & msg);
		void send_to_all_peers(const std::string & msg);
		virtual std::vector<std::unique_ptr<c_peer_reference>> get_peer_list();
		size_t number_of_connected_peers() const;
		void disconnect_peer(const c_peer_reference & peer);
		void delete_session(const c_peer_reference & peer_info); ///< must be called after lock m_sessions_mtx
	protected:
		virtual boost::asio::ip::tcp::socket connect_to_peer(const c_peer_reference & peer_info) = 0;
		boost::asio::io_context & get_io_context();
		virtual std::unique_ptr<c_peer_reference> get_accept_remote_peer_info(const boost::asio::ip::tcp::socket & socket) const = 0;
		void remove_all_sessions();
	private:
		static constexpr size_t s_connection_limit = 6;
		mutable std::shared_mutex m_sessions_mtx;
		std::vector<std::weak_ptr<c_tcp_session>> m_sessions;
		read_handler m_read_handler;
		new_peer_handler m_new_peer_handler;
		boost::asio::io_context m_io_context;
		boost::asio::ip::tcp::socket m_accept_socket;
		boost::asio::ip::tcp::acceptor m_acceptor;
		std::vector<std::thread> m_io_context_thread;
		
		void add_peer(std::unique_ptr<c_peer_reference> && peer_info, boost::asio::ip::tcp::socket && connected_socket, bool is_server); ///< must be called after lock m_sessions_mtx
		auto get_iterator_to_session(const c_peer_reference & peer_info); ///< must be called after lock m_sessions_mtx
		void do_accept();
		/// m_sessions_mtx must be locked before call
		void remove_closed_sessions();
};

#endif // C_P2P_SESSION_MANAGER_HPP
