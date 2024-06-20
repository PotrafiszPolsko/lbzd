#ifndef MEDIATOR_STUB_HPP
#define MEDIATOR_STUB_HPP

#include "../src/mediator.hpp"

class c_mediator_stub : public c_mediator {
	public:
		std::unique_ptr<t_mediator_command_response> notify(const t_mediator_command_request & request) override {};
		std::unique_ptr<t_mediator_command_response> notify(const t_mediator_command_request & request) const override {};
};

#endif // MEDIATOR_STUB_HPP
