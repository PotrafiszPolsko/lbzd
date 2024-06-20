#ifndef INCLUDE_rpc_exec_hpp
#define INCLUDE_rpc_exec_hpp

#include <functional>
#include <mutex>
#include "utils_json.hpp"

class c_rpc_module;

class c_rpc_exec {
	public:
		c_rpc_exec() = default;
		nlohmann::json execute(const nlohmann::json & cmd);
		void add_method( const std::string & method, std::function<std::pair<std::string , nlohmann::json> (const nlohmann::json & )> && exec );
		void install_rpc_handlers();
		~c_rpc_exec() = default;
		void set_rpc_module(c_rpc_module &rpc_module);
	private:
		std::map<std::string, std::function<std::pair<std::string , nlohmann::json> (const nlohmann::json & )>> m_cmd_map;
		std::mutex m_mutex;
		c_rpc_module *m_rpc_module = nullptr;
};

#endif


