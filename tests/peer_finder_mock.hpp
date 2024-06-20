#ifndef C_PEER_FINDER_MOCK_HPP
#define C_PEER_FINDER_MOCK_HPP

#include "../src/peer_finder.hpp"
#include <gmock/gmock.h>

class c_peer_finder_mock : public c_peer_finder {
	public:
		c_peer_finder_mock(const std::filesystem::path & datadir_path);
		MOCK_METHOD(bool, is_my_address, (const std::string & public_address_port), (const, override));
		MOCK_METHOD(std::vector<t_peer_finder_address>, load_peers, (), (override));
};

#endif // C_PEER_FINDER_MOCK_HPP
