#include "main_module_builder.hpp"
#include "p2p_module_builder.hpp"
#include "rpc_module_builder.hpp"

void c_main_module_builder::set_program_options(const boost::program_options::variables_map & vm) {
	m_variable_map = vm;
}

template<>
auto c_main_module_builder::build_component<c_blockchain_module_builder>(const boost::program_options::variables_map & vm, c_main_module & main_module) const {
	c_blockchain_module_builder builder;
	builder.set_program_options(vm);
	return builder.get_result(dynamic_cast<c_mediator&>(main_module));
}

std::unique_ptr<c_main_module> c_main_module_builder::get_result() {
	auto main_module = std::make_unique<c_main_module>();
	main_module->m_blockchain_module = build_component<c_blockchain_module_builder>(m_variable_map, *main_module);
	main_module->m_rpc_module = build_component<c_rpc_module_builder>(m_variable_map, *main_module);
	main_module->m_p2p_module = build_component<c_p2p_module_builder>(m_variable_map, *main_module);
	return main_module;
}
