#ifndef C_P2P_SESSION_MANAGER_TCP_HPP
#define C_P2P_SESSION_MANAGER_TCP_HPP

#include "session.hpp"
#include <condition_variable>
#include <thread>
#include <boost/asio/io_service.hpp>
#include <boost/asio/use_future.hpp>
#include <shared_mutex>
#include "p2p_session_manager.hpp"



class c_p2p_session_manager_tcp : public c_p2p_session_manager {
	public:
		c_p2p_session_manager_tcp(read_handler read_handler, new_peer_handler new_peer_handler, boost::asio::ip::tcp::endpoint listen_endpoint);
		~c_p2p_session_manager_tcp() override = default;
	protected:
		boost::asio::ip::tcp::socket connect_to_peer(const c_peer_reference & peer_info) override;
		std::unique_ptr<c_peer_reference> get_accept_remote_peer_info(const boost::asio::ip::tcp::socket & socket) const override;
};

#endif // C_P2P_SESSION_MANAGER_TCP_HPP
