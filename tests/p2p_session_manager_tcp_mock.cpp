#include "p2p_session_manager_tcp_mock.hpp"

c_p2p_session_manager_tcp_mock::c_p2p_session_manager_tcp_mock(read_handler read_handler, boost::asio::ip::tcp::endpoint listen_endpoint) 
	:
	  c_p2p_session_manager_tcp(read_handler, new_peer_handler{}, listen_endpoint)
{
}
