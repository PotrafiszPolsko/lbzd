#include <shared_mutex>
#include "utils-node.hpp"
#include "p2p_session_manager_tor.hpp"
#include "tor_socks5_provider.hpp"
#include "logger.hpp"

c_p2p_session_manager_tor::c_p2p_session_manager_tor(read_handler read_handler, new_peer_handler new_peer_handler, unsigned short hidden_service_port, const std::filesystem::path & datadir_path, unsigned short socks5_port, unsigned short control_port)
:
	c_p2p_session_manager(read_handler, new_peer_handler, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), hidden_service_port))),
	m_socks5_port(socks5_port),
	m_control_port(control_port),
	m_hidden_service_port(hidden_service_port),
	m_tor_control(m_control_port)
{
	m_tor_control.authorize();
	m_tor_address = read_tor_address(hidden_service_port, datadir_path);
}

boost::asio::ip::tcp::socket c_p2p_session_manager_tor::connect_to_peer(const c_peer_reference & peer_info) {
	LOG(debug)<<"Trying to add peer";
	LOG(debug)<<"Try to add peer " << peer_info.to_string();
	const auto & peer_tor = dynamic_cast<const c_peer_reference_onion &>(peer_info);
	if (peer_tor.is_hidden_remote()) {
		throw std::invalid_argument("Cannot connect to hidden peer " + peer_tor.to_string());
	}
	socks5::tor_endpoint tor_endpoint;
	tor_endpoint.m_onion_address = peer_tor.get_onion_address();
	tor_endpoint.m_onion_port = peer_tor.get_port();
	tor_socks5_credentials socks5_credentials = peer_tor.get_socks5_credentials();

	auto & io_context = get_io_context();
	c_tor_socks5_provider socks5_provider(io_context, m_socks5_port);
	const auto timeout = std::chrono::seconds(30);
	boost::asio::ip::tcp::socket connect_socket(io_context);
	const auto number_of_connect_attempts = 3;
	bool connected = false;
	for (unsigned i = 0; i < number_of_connect_attempts; i++) {
		try {
			connect_socket = socks5_provider.connect_to_onion_address(tor_endpoint, socks5_credentials, timeout);
			connected = true;
			break;
		} catch (const std::exception & exception) {
			LOG(debug) << "connect to onion address error: " << exception.what();
		}
	}
	if (!connected) throw std::runtime_error("Connection error");
	LOG(debug)<<"Trying to add peer - DONE";
	return connect_socket;
}

std::unique_ptr<c_peer_reference> c_p2p_session_manager_tor::get_accept_remote_peer_info(const boost::asio::ip::tcp::socket &) const {
	std::unique_ptr<c_peer_reference> peer_info = std::make_unique<c_peer_reference_onion>();
	return peer_info;
}

unsigned short c_p2p_session_manager_tor::get_hidden_service_port() const {
	return m_hidden_service_port;
}

std::string c_p2p_session_manager_tor::read_tor_address(unsigned short hidden_service_port, const std::filesystem::path & datadir_path) {
	return m_tor_control.read_tor_address(hidden_service_port, datadir_path);
}

void c_p2p_session_manager_tor::new_identity() {
	LOG(debug)<<"generate new TOR identity";
	m_tor_control.new_identity();
	LOG(debug)<<"close old TOR sessions";
	remove_all_sessions();
}

std::string c_p2p_session_manager_tor::get_tor_address() const {
	return m_tor_address;
}


