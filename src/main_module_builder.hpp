#ifndef MAIN_MODULE_BUILDER_HPP
#define MAIN_MODULE_BUILDER_HPP

#include "main_module.hpp"
#include <boost/program_options/variables_map.hpp>
#include <type_traits>
#include "blockchain_module_builder.hpp"

class c_main_module_builder {
	public:
		void set_program_options(const boost::program_options::variables_map & vm);
		std::unique_ptr<c_main_module> get_result();
	private:
		boost::program_options::variables_map m_variable_map;
		template <class T_BUILDER>
		auto build_component(const boost::program_options::variables_map & vm, c_main_module & main_module) const;
};

template<class T_BUILDER>
auto c_main_module_builder::build_component(const boost::program_options::variables_map & vm, c_main_module & main_module) const {
	T_BUILDER builder;
	builder.set_program_options(vm);
	return builder.get_result(dynamic_cast<c_mediator&>(main_module));
}



#endif // MAIN_MODULE_BUILDER_HPP
