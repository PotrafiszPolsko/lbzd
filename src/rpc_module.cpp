#include "rpc_module.hpp"
#include "logger.hpp"

c_rpc_module::c_rpc_module(std::unique_ptr<c_rpc_server_base> && rpc_server, c_mediator & mediator)
	:
	c_component (mediator),
	m_rpc_server( std::move(rpc_server) )
{
}

c_rpc_server_base &c_rpc_module::get_rpc_server() {
	return * m_rpc_server;
}

void c_rpc_module::start_execution_impl() {
	m_thread_rpc = std::make_unique< std::thread >( [this]() {
		m_rpc_server->run_and_block();
	});
}

void c_rpc_module::run() {
	LOG(info) << "Run rpc module";
	const auto exec = m_rpc_server->get_exec();
	exec->install_rpc_handlers();
	start_execution_impl();
}
