#include "main_module_mock_builder.hpp" 

c_main_module_mock_builder::c_main_module_mock_builder() 
    :
	m_main_module(std::make_unique<c_main_module>())
{
}

std::unique_ptr<c_main_module> c_main_module_mock_builder::get_result() {
	return std::move(m_main_module);
}

void c_main_module_mock_builder::set_blockchain_module(std::unique_ptr<c_blockchain_module> &&blockchain_module) {
	m_main_module->m_blockchain_module = std::move(blockchain_module);
}

void c_main_module_mock_builder::set_p2p_module(std::unique_ptr<c_p2p_module> &&p2p_module) {
	m_main_module->m_p2p_module = std::move(p2p_module);
}

void c_main_module_mock_builder::set_rpc_module(std::unique_ptr<c_rpc_module> &&rpc_module) {
	m_main_module->m_rpc_module = std::move(rpc_module);
}
