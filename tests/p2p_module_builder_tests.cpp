#include "p2p_module_builder_tests.hpp"
#include "peer_finder_mock.hpp"
#include "port_forwarder_mock.hpp"
#include "mediator_mock.hpp"
#include "../src/p2p_module.hpp"

std::unique_ptr<c_p2p_module> c_p2p_module_builder_tests::build_p2p_module(c_mediator_mock & mediator_mock) {
	auto p2p_module = std::make_unique<c_p2p_module>(mediator_mock);
	p2p_module->m_session_manager_tcp = build_tcp_session_manager(*p2p_module);
	p2p_module->m_session_manager_tor = build_tor_session_manager(*p2p_module);
	const std::filesystem::path path = "./";
	p2p_module->m_peer_finder = std::make_unique<c_peer_finder_mock>(path);
	auto &p2p_module_obj = (*p2p_module);
	auto port_forwarder = ([&p2p_module_obj](const std::string & ip, const unsigned short port){p2p_module_obj.broadcast_external_ip(ip, port);});
	p2p_module->m_port_forwarder = std::make_unique<c_port_forwarder_mock>(port_forwarder);
	return p2p_module;
}

std::unique_ptr<c_p2p_session_manager_tcp_mock> c_p2p_module_builder_tests::build_tcp_session_manager(c_p2p_module & p2p_module) const {
	const auto listen_ip = boost::asio::ip::address_v4::from_string("127.0.0.1");
	const auto listen_port = 22083;
	const boost::asio::ip::tcp::endpoint listen_endpoint(listen_ip, listen_port);
	read_handler handler = [&p2p_module](const c_peer_reference & endpoint, span<const unsigned char> data){
		p2p_module.read_handler_tcp(endpoint, data);
	};
	auto session_manager_tcp = std::make_unique<c_p2p_session_manager_tcp_mock>(handler, listen_endpoint);
	return session_manager_tcp;
}

std::unique_ptr<c_p2p_session_manager_tor_mock> c_p2p_module_builder_tests::build_tor_session_manager(c_p2p_module & p2p_module) const {
	const auto listen_port = 22086;
	const auto datadir_path = "./";
	read_handler handler = [&p2p_module](const c_peer_reference & endpoint, span<const unsigned char> data){
		p2p_module.read_handler_tcp(endpoint, data);
	};
	const auto tor_control_port = 9051;
	const auto tor_socks_port = 9050;
	auto session_manager_tor = std::make_unique<c_p2p_session_manager_tor_mock>(handler, listen_port, datadir_path, tor_socks_port, tor_control_port);
	return session_manager_tor;
}
