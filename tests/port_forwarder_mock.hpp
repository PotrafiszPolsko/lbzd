#ifndef C_PORT_FORWARDER_MOCK_HPP
#define C_PORT_FORWARDER_MOCK_HPP

#include "../src/port_forwarder.hpp"
#include <gmock/gmock.h>

class c_port_forwarder_mock : public c_port_forwarder {
	public:
		c_port_forwarder_mock(t_broadcast_ip_callback broadcast_ip_callback);
		using pair_string_to_short = std::pair<std::string, unsigned short>;
		MOCK_METHOD(std::optional<pair_string_to_short>, get_my_public_ip, (), (const, override));
};

#endif // C_PORT_FORWARDER_MOCK_HPP
