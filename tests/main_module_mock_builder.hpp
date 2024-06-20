#ifndef MAIN_MODULE_MOCK_BUILDER_HPP
#define MAIN_MODULE_MOCK_BUILDER_HPP

#include "../src/main_module.hpp"

class c_main_module_mock_builder {
	public:
		c_main_module_mock_builder();
		
		std::unique_ptr<c_main_module> get_result();
		void set_blockchain_module(std::unique_ptr<c_blockchain_module> &&blockchain_module);
		void set_p2p_module(std::unique_ptr<c_p2p_module> &&p2p_module);
		void set_rpc_module(std::unique_ptr<c_rpc_module> &&rpc_module);
	private:
		std::unique_ptr<c_main_module> m_main_module;
};

#endif // MAIN_MODULE_MOCK_BUILDER_HPP
