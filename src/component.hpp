#ifndef COMPONENT_HPP
#define COMPONENT_HPP

#include "mediator.hpp"


class c_component {
	public:
		c_component(c_mediator & mediator);
		virtual ~c_component() = default;
		std::unique_ptr<t_mediator_command_response> notify_mediator(const t_mediator_command_request & request);
		std::unique_ptr<t_mediator_command_response> notify_mediator(const t_mediator_command_request & request) const;
		virtual void run() = 0;
	private:
		c_mediator & m_mediator;
};

#endif // COMPONENT_HPP
