#ifndef WALLET_MODULE_BUILDER_HPP
#define WALLET_MODULE_BUILDER_HPP

#include "component_builder.hpp"
#include "wallet_module_interface.hpp"

class c_wallet_module_builder : public c_component_builder {
	public:
		void set_program_options(const boost::program_options::variables_map & vm) override;
		std::unique_ptr<c_wallet_module_interface> get_result(c_mediator & mediator) const;
	private:
		boost::program_options::variables_map m_variable_map;
		std::unique_ptr<c_wallet> build_wallet() const;
};

#endif // WALLET_MODULE_BUILDER_HPP
