#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/use_future.hpp>
#include <iostream>
#include "tor_socks5_credentials.hpp"
#include "tor_socks5_provider.hpp"
#include "logger.hpp"

c_tor_socks5_provider::c_tor_socks5_provider(boost::asio::io_context & io_context, unsigned short onion_port)
	:
	m_onion_port(onion_port),
	m_timeout(),
	m_socket(io_context)
{

}

boost::asio::ip::tcp::socket c_tor_socks5_provider::connect_to_onion_address(const socks5::tor_endpoint& tor_endpoint,
															  const tor_socks5_credentials & tor_credentials,
															  const std::chrono::seconds & timeout) {
	m_timeout = std::chrono::steady_clock::now() + timeout;
	const auto socks5_endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), m_onion_port);
	LOG(debug)<<"TOR SOCKS5 Provider - Connecting...";
	m_socket.connect(socks5_endpoint);

	send_auth_select();
	receive_auth_select();
	send_auth_userpass(tor_credentials);
	receive_auth_userpass();
	request_connect(tor_endpoint);
	response_connect();

	LOG(debug)<<"TOR SOCKS5 Provider - Connected !!!";
	return std::move(m_socket);
}

void c_tor_socks5_provider::check_future_status(const std::future_status status) {
	if (status == std::future_status::timeout) {
		throw std::runtime_error("check_future_status : timeout");
	} else if (status == std::future_status::deferred) {
		throw std::runtime_error("check_future_status : future status == deferred");
	}
}

void c_tor_socks5_provider::send_auth_select() {
	LOG(debug)<<"Start authentication method negotiation...";
	socks5::request_auth_select request_auth_select;
	boost::asio::write(m_socket, request_auth_select.buffers());
	LOG(debug)<<"Authentication negotiation OK";
}

void c_tor_socks5_provider::receive_auth_select() {
	LOG(debug)<<"Receive authenticate information";
	socks5::response_auth_select response_auth_select;
	boost::asio::read(m_socket, response_auth_select.buffers());
}

void c_tor_socks5_provider::send_auth_userpass(const tor_socks5_credentials & tor_credentials) {
	LOG(debug)<<"Send user/password...";
	socks5::request_auth_userpass request_auth_select;
	request_auth_select.set_username(tor_credentials.m_username_soks5);
	request_auth_select.set_password(tor_credentials.m_password_soks5);
	boost::asio::write(m_socket, request_auth_select.buffers());
	LOG(debug)<<"Sended user/password OK";
}

void c_tor_socks5_provider::receive_auth_userpass() {
	LOG(debug)<<"Receive user/password information";
	socks5::response_auth_select response_auth_select;
	boost::asio::read(m_socket, response_auth_select.buffers());
}

void c_tor_socks5_provider::request_connect(const socks5::tor_endpoint &tor_endpoint) {
	LOG(debug)<<"Try to connect onion address : "<< tor_endpoint.m_onion_address;
	socks5::request_connect request_connect(tor_endpoint);
	boost::asio::write(m_socket, request_connect.buffers());
	LOG(debug)<<"Connected to onion address : "<< tor_endpoint.m_onion_address;
}

void c_tor_socks5_provider::response_connect() {
	socks5::response_connect response_connect;
	const auto readed_bytes = boost::asio::read(m_socket, response_connect.buffers());
	unsigned char response = response_connect.m_rep;
	LOG(debug) <<"Read " << readed_bytes << " bytes";
	LOG(debug) << "Status response code is : " << std::to_integer<int>(static_cast<std::byte>(response));
	if (response == (0x00)) {
		LOG(debug)<<"Status response text is : Success";
	}
	else if (response == (0x01)) {
		LOG(debug)<<"Status response text is : general SOCKS server failure";
	}
	else if (response == (0x02)) {
		LOG(debug)<<"Status response text is : connection not allowed by ruleset";
	}
	else if (response == (0x03)) {
		LOG(debug)<<"Status response text is : Network unreachable";
	}
	else if (response == (0x04)) {
		LOG(debug)<<"Status response text is : Host unreachable";
	}
	else if (response == (0x05)) {
		LOG(debug)<<"Status response text is : Connection refused";
	}
	else if (response == (0x06)) {
		LOG(debug)<<"Status response text is : TTL expired";
	}
	else if (response == (0x07)) {
		LOG(debug)<<"Status response text is : Command not supported";
	}
	else if (response == (0x08)) {
		LOG(debug)<<"Status response text is : Address type not supported";
	}
	else {
		LOG(debug)<<"Status response text is : unassigned";
	}
	if (response != (0x00)) {
		LOG(debug)<<"Response is other than 0x00, shutdown socket";
		m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
		m_socket.close();
		throw std::runtime_error("Cannot connect to " + response_connect.get_address().to_string());
	}
}
