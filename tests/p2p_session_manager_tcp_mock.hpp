#ifndef C_P2P_SESSION_MANAGER_TCP_MOCK_HPP
#define C_P2P_SESSION_MANAGER_TCP_MOCK_HPP

#include <gmock/gmock.h>
#include "../src/p2p_session_manager_tcp.hpp"


class c_p2p_session_manager_tcp_mock : public  c_p2p_session_manager_tcp {
	public:
		c_p2p_session_manager_tcp_mock(read_handler read_handler, new_peer_handler new_peer_handler, boost::asio::ip::tcp::endpoint listen_endpoint);
};

#endif // C_P2P_SESSION_MANAGER_TCP_MOCK_HPP
