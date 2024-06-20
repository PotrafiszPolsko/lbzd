#ifndef P2P_MODULE_MOCK_HPP
#define P2P_MODULE_MOCK_HPP

#include <gmock/gmock.h>
#include "../src/p2p_module.hpp"
#include "mediator_stub.hpp"

class c_p2p_module_mock : public c_p2p_module {
	public:
		c_p2p_module_mock();
		MOCK_METHOD(void, broadcast_transaction, (const c_transaction & transaction, bool only_tor), (override));
		MOCK_METHOD(void, broadcast_block, (const c_block & block), (override));
		MOCK_METHOD(std::vector<std::unique_ptr<c_peer_reference> >, get_peers_tcp, (), (const, override));
		MOCK_METHOD(std::vector<std::unique_ptr<c_peer_reference> >, get_peers_tor, (), (const, override));
		MOCK_METHOD(void, new_identity_tor, (), (override));
	private:
		static c_mediator_stub m_mediator_stub;
};

#endif // P2P_MODULE_MOCK_HPP

