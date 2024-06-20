#include "p2p_session_manager_tor_mock.hpp"

c_p2p_session_manager_tor_mock::c_p2p_session_manager_tor_mock(read_handler read_handler, unsigned short hidden_service_port, const std::filesystem::path & datadir_path,
                                                               unsigned short socks5_port, unsigned short control_port)
	:
	  c_p2p_session_manager_tor(read_handler, new_peer_handler{}, hidden_service_port, datadir_path, socks5_port, control_port)
{
}
