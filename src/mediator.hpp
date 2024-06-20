#ifndef MEDIATOR_H
#define MEDIATOR_H

#include <memory>
#include "mediator_commands.hpp"

class c_mediator {
	public:
		virtual ~c_mediator() = default;
		virtual std::unique_ptr<t_mediator_command_response> notify(const t_mediator_command_request & request) = 0;
		virtual std::unique_ptr<t_mediator_command_response> notify(const t_mediator_command_request & request) const = 0;
};

#endif // MEDIATOR_H
