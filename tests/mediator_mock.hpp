#ifndef MEDIATOR_MOCK_HPP
#define MEDIATOR_MOCK_HPP

#include <gmock/gmock.h>
#include "../src/mediator.hpp"

class c_mediator_mock : public c_mediator {
	public:
		MOCK_METHOD(
			std::unique_ptr<t_mediator_command_response>,
			notify,
			(const t_mediator_command_request & request),
			(override));
		MOCK_METHOD(
			std::unique_ptr<t_mediator_command_response>,
			notify,
			(const t_mediator_command_request & request),
			(const, override));
};

#endif // MEDIATOR_MOCK_HPP
