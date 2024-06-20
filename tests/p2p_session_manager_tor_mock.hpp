#ifndef C_P2P_SESSION_MANAGER_TOR_MOCK_HPP
#define C_P2P_SESSION_MANAGER_TOR_MOCK_HPP

#include <gmock/gmock.h>
#include "../src/p2p_session_manager_tor.hpp"


class c_p2p_session_manager_tor_mock : public c_p2p_session_manager_tor {
	public:
		c_p2p_session_manager_tor_mock(read_handler read_handler, unsigned short hidden_service_port, const std::filesystem::path & datadir_path,
		                               unsigned short socks5_port, unsigned short control_port);
		MOCK_METHOD(std::vector<std::unique_ptr<c_peer_reference>>, get_peer_list, (), (override));
		MOCK_METHOD(std::string, get_tor_address, (), (const, override));
		MOCK_METHOD(unsigned short, get_hidden_service_port, (), (const, override));
};

#endif // C_P2P_SESSION_MANAGER_TOR_MOCK_HPP
