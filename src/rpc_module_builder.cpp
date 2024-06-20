#include "rpc_module_builder.hpp"
#include <fstream>
#include <sodium.h>
#include <boost/asio/io_context.hpp>

void c_rpc_module_builder::set_program_options(const boost::program_options::variables_map &vm) {
    m_variable_map = vm;
}

std::unique_ptr<c_rpc_server> c_rpc_module_builder::build_rpc_server(std::shared_ptr<c_rpc_exec> rpc_exec) const {
	const uint16_t tcpport = m_variable_map.at("rpc-tcp-port").as<uint16_t>();
	const auto address = m_variable_map.at("rpc-tcp-address").as<std::string>();

	boost::asio::io_context svc;
	boost::asio::ip::tcp::resolver resolver(svc);
	boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), address, std::to_string(tcpport));
	boost::asio::ip::tcp::endpoint iter = *resolver.resolve(query);
	const auto endpoint = boost::asio::ip::tcp::endpoint(iter.address() ,tcpport);
	const auto auth_string = get_auth_string();
	auto rpc_server = std::make_unique<c_rpc_server>(rpc_exec, endpoint, auth_string);
	return rpc_server;
}

std::string c_rpc_module_builder::string_to_base64(const std::string auth_string) const {
	std::string auth_string_base64(auth_string.size()*2, '\0');
	sodium_bin2base64(auth_string_base64.data(), auth_string_base64.size(),
					  reinterpret_cast<const unsigned char *>(auth_string.data()), auth_string.size(),
					  sodium_base64_VARIANT_ORIGINAL);
	auth_string_base64.erase(
				std::remove(auth_string_base64.begin(), auth_string_base64.end(), '\0'),
				auth_string_base64.end());

	return auth_string_base64;
}

std::string c_rpc_module_builder::get_auth_string() const {
	const auto rpcuser = m_variable_map.at("rpcuser").as<std::string>();
	const auto rpcpassword = m_variable_map.at("rpcpassword").as<std::string>();
	if (rpcpassword.empty()) { // cookie file
		const std::filesystem::path cookie_file_path = std::filesystem::path(m_variable_map.at("datadir").as<std::filesystem::path>()) / ".cookie";
		auto cookie_file_content = create_cookie_file(cookie_file_path);
		return cookie_file_content;
	}
	const auto auth_string = rpcuser + ':' + rpcpassword;
	const std::string auth_string_base64 = string_to_base64(auth_string);
	return auth_string_base64;
}

std::string c_rpc_module_builder::create_cookie_file(const std::filesystem::path & path) const {
	std::array<unsigned char, 32> cookie_random_content;
	randombytes_buf(cookie_random_content.data(), cookie_random_content.size());
	std::string cookie_random_content_hex(cookie_random_content.size()*2+1, '\0');
	sodium_bin2hex(cookie_random_content_hex.data(), cookie_random_content_hex.size(), cookie_random_content.data(), cookie_random_content.size());
	std::string full_content = "__cookie__:" + cookie_random_content_hex;
	std::ofstream cookie_file(path);
	cookie_file << full_content;
	return string_to_base64(full_content);
}

std::unique_ptr<c_rpc_module> c_rpc_module_builder::get_result(c_mediator &mediator) const {
    auto rpc_exec = std::make_shared<c_rpc_exec>();
    auto rpc_server = build_rpc_server(rpc_exec);
	
    auto rpc_module = std::make_unique<c_rpc_module>(std::move(rpc_server) , mediator);
    rpc_exec->set_rpc_module(*rpc_module);
    return rpc_module;
}
