#ifndef C_RPC_MODULE_BUILDER_HPP
#define C_RPC_MODULE_BUILDER_HPP

#include "component_builder.hpp"
#include "rpc_module.hpp"

class c_rpc_module_builder : public c_component_builder {
	public:
		void set_program_options(const boost::program_options::variables_map & vm) override;
		std::unique_ptr<c_rpc_module> get_result(c_mediator & mediator) const;
	private:
		boost::program_options::variables_map m_variable_map;
		std::unique_ptr<c_rpc_server> build_rpc_server(std::shared_ptr<c_rpc_exec> rpc_exec) const;
		std::string get_auth_string() const;
		/**
		 * @brief create_cookie_file
		 * @return cookie file content
		 */
		std::string create_cookie_file(const std::filesystem::path & path) const;
		std::string string_to_base64(const std::string auth_string) const;
};

#endif // C_RPC_MODULE_BUILDER_HPP
