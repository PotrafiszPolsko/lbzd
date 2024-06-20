#ifndef C_P2P_MODULE_BUILDER_TESTS_HPP
#define C_P2P_MODULE_BUILDER_TESTS_HPP

#include "mediator_mock.hpp"
#include "p2p_session_manager_tcp_mock.hpp"
#include "p2p_session_manager_tor_mock.hpp"
#include "../src/p2p_module.hpp"

class c_p2p_module_builder_tests {
	public:
		std::unique_ptr<c_p2p_module> build_p2p_module(c_mediator_mock & mediator_mock);
	private:
		std::unique_ptr<c_p2p_session_manager_tcp_mock> build_tcp_session_manager(c_p2p_module & p2p_module) const;
		std::unique_ptr<c_p2p_session_manager_tor_mock> build_tor_session_manager(c_p2p_module & p2p_module) const;
};

#endif // C_P2P_MODULE_BUILDER_TESTS_HPP
