#ifndef C_RPC_MODULE_HPP
#define C_RPC_MODULE_HPP

#include "component.hpp"
#include "rpc_server.hpp"
#include <thread>

class c_rpc_module final : public c_component {
		friend class c_rpc_module_builder;
		friend std::unique_ptr<c_rpc_module> std::make_unique<c_rpc_module>(std::unique_ptr<c_rpc_server_base> && , c_mediator &);
	public:
		void run() override;
		c_rpc_module(std::unique_ptr<c_rpc_server_base> && rpc_server, c_mediator & mediator);
		c_rpc_server_base & get_rpc_server();
		void start_execution_impl();
	private:
		std::unique_ptr<c_rpc_server_base> m_rpc_server;
		std::unique_ptr< std::thread > m_thread_rpc;
};

#endif // RPC_MODULE_HPP
