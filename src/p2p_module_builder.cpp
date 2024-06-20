#include "p2p_module_builder.hpp"
#include <boost/asio/ip/address.hpp>
#include "logger.hpp"

void c_p2p_module_builder::set_program_options(const boost::program_options::variables_map & vm) {
	m_variable_map = vm;
}

void c_p2p_module_builder::ask_for_peers(c_p2p_module & p2p_module) const {
	const auto peers_tcp = p2p_module.get_peers_tcp();
	const auto peers_tor = p2p_module.get_peers_tor();
	ask_for_peers(p2p_module, peers_tcp);
	ask_for_peers(p2p_module, peers_tor);
}

void c_p2p_module_builder::ask_for_peers(c_p2p_module & p2p_module, const std::vector<std::unique_ptr<c_peer_reference>> & peer_list) const {
	for (const auto & peer : peer_list)
		p2p_module.ask_for_peers(*peer);
}

std::unique_ptr<c_p2p_module> c_p2p_module_builder::get_result(c_mediator & mediator) const {
	auto p2p_module = std::make_unique<c_p2p_module>(mediator);
	p2p_module->m_session_manager_tcp = build_tcp_session_manager(*p2p_module);
	const auto listen_port = m_variable_map.at("bindport").as<unsigned short>();
	p2p_module->m_session_manager_tor = build_tor_session_manager(*p2p_module);
	p2p_module->m_peer_finder = build_peer_finder();
	auto &p2p_module_obj = *p2p_module;
	p2p_module->m_port_forwarder = std::make_unique<c_port_forwarder>([&p2p_module_obj](const std::string & ip, const unsigned short port)
															{p2p_module_obj.broadcast_external_ip(ip, port);});
	connect_to_peers(*p2p_module->m_session_manager_tcp, *p2p_module->m_session_manager_tor);
	p2p_module->connect_to_saved_peers();
	ask_for_peers(*p2p_module);
	if(m_variable_map.at("portforwarder").as<bool>())
		p2p_module->start_port_forwarding(listen_port);
	if (m_variable_map.count("externalip") == 1) {
		auto external_ip = m_variable_map.at("externalip").as<std::string>();
		LOG(debug) << "Set external address: " << external_ip << ':' << listen_port;
		p2p_module->m_my_public_address_form_commandline = std::make_pair(external_ip, listen_port);
		assert(p2p_module->m_my_public_address_form_commandline.has_value());
	}
	const bool enable_seed_node = m_variable_map.at("enable-seed-node-connection").as<bool>();
	if (enable_seed_node) {
		if (!p2p_module->am_i_seed_node()) {
			while (p2p_module->number_of_connected_peers() == 0) {
				p2p_module->connect_to_random_seed_node();
			}
		}
	}
	return p2p_module;
}

void c_p2p_module_builder::connect_to_peers(c_p2p_session_manager_tcp & session_manager_tcp,
											c_p2p_session_manager_tor & session_manager_tor) const {
	if (m_variable_map.count("addnode") == 0) return;
	const auto addnode_arguments = m_variable_map.at("addnode").as<std::vector<std::string>>();
	for (const auto & addnode : addnode_arguments) {
		const auto colon_pos = addnode.find_last_of(':');
		if(colon_pos!=std::string::npos) {
			auto address_str = addnode.substr(0, colon_pos);
			const auto port_str = addnode.substr(colon_pos + 1);
			const auto port = static_cast<unsigned short>(std::stoul(port_str));
			if (address_str.find(".onion") == std::string::npos) {
				if(address_str.front()=='[' && address_str.back()==']') {
					address_str.erase(address_str.begin());
					address_str.erase(address_str.end()-1);
				}
				boost::system::error_code ec;
				const auto ip = boost::asio::ip::make_address(address_str, ec);
				try {
					if(!ec) {
						c_peer_reference_tcp peer_reference(ip, port);
						session_manager_tcp.add_peer(peer_reference);
					} else {
						boost::asio::io_context io_context;
						boost::asio::ip::tcp::resolver resolver(io_context);
						boost::asio::ip::tcp::resolver::query query(address_str, port_str);
						boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
						c_peer_reference_url peer_reference(it->endpoint());
						session_manager_tcp.add_peer(peer_reference);
					}
				} catch (const std::exception & exception) {
					LOG(warning) << "Connection to peer " << addnode << " error: " << exception.what();
				}
			} else {
				const auto onion_address = address_str;
				c_peer_reference_onion peer_reference(onion_address, port);
				session_manager_tor.add_peer(peer_reference);
			}
		} else throw std::runtime_error("most likely no port specified");
	}
}

std::unique_ptr<c_p2p_session_manager_tcp> c_p2p_module_builder::build_tcp_session_manager(c_p2p_module & p2p_module) const {
	const auto listen_ip = boost::asio::ip::address_v4::from_string(m_variable_map.at("bindaddress").as<std::string>());
	const auto listen_port = m_variable_map.at("bindport").as<unsigned short>();
	const boost::asio::ip::tcp::endpoint listen_endpoint(listen_ip, listen_port);
	read_handler read_handler = [&p2p_module](const c_peer_reference & endpoint, span<const unsigned char> data){
		p2p_module.read_handler_tcp(endpoint, data);
	};
	new_peer_handler new_peer_handler = [&p2p_module](const c_peer_reference & endpoint){
		p2p_module.new_peer_handler(endpoint);
	};

	auto session_manager_tcp = std::make_unique<c_p2p_session_manager_tcp>(read_handler, new_peer_handler, listen_endpoint);
	return session_manager_tcp;
}

std::unique_ptr<c_p2p_session_manager_tor> c_p2p_module_builder::build_tor_session_manager(c_p2p_module & p2p_module) const {
	const auto listen_port = m_variable_map.at("onionport").as<unsigned short>();
	const auto datadir_path = m_variable_map.at("datadir").as<std::filesystem::path>();
	read_handler read_handler = [&p2p_module](const c_peer_reference & endpoint, span<const unsigned char> data){
		p2p_module.read_handler_tcp(endpoint, data);
	};
	new_peer_handler new_peer_handler = [&p2p_module](const c_peer_reference & endpoint){
		p2p_module.new_peer_handler(endpoint);
	};
	const auto tor_control_port = m_variable_map.at("torcontrolport").as<unsigned short>();
	const auto tor_socks_port = m_variable_map.at("torsocksport").as<unsigned short>();
	auto session_manager_tor = std::make_unique<c_p2p_session_manager_tor>(read_handler, new_peer_handler, listen_port, datadir_path, tor_socks_port, tor_control_port);
	return session_manager_tor;
}

std::unique_ptr<c_peer_finder> c_p2p_module_builder::build_peer_finder() const {
	const std::filesystem::path datadir_path = m_variable_map.at("datadir").as<std::filesystem::path>();
	auto peer_finder = std::make_unique<c_peer_finder>(datadir_path);
	return peer_finder;
}
