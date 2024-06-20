#include "component.hpp"

c_component::c_component(c_mediator & mediator)
:
	m_mediator(mediator)
{
}

std::unique_ptr<t_mediator_command_response> c_component::notify_mediator(const t_mediator_command_request & request) {
	return m_mediator.notify(request);
}

std::unique_ptr<t_mediator_command_response> c_component::notify_mediator(const t_mediator_command_request & request) const {
	return m_mediator.notify(request);
}
