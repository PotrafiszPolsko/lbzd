#include "peer_reference.hpp"
#include <sstream>
#include <iostream>
#include <sodium.h>

c_peer_reference::c_peer_reference(c_peer_reference::type type)
	:
		m_type(type)
{}

c_peer_reference::type c_peer_reference::get_type() const {
	return m_type;
}

bool c_peer_reference::operator==(const c_peer_reference & other) const noexcept {
	if (typeid(*this) != typeid(other)) return false;
	return is_equal(other);
}

bool c_peer_reference::operator<(const c_peer_reference & other) const noexcept {
	if (typeid(*this) == typeid(other)) return (*this < other);
	return (typeid(*this).hash_code() < typeid(other).hash_code()); // no oprtator < for std::type_info
}

////////////////////////////////////////////////////////////////////////////

c_peer_reference_tcp::c_peer_reference_tcp()
	:
	  c_peer_reference(c_peer_reference::type::e_tcp)
{
}

c_peer_reference_tcp::c_peer_reference_tcp(const boost::asio::ip::address & address, unsigned short port)
	:
	c_peer_reference(c_peer_reference::type::e_tcp),
	m_endpoint(address, port)
{}

c_peer_reference_tcp::c_peer_reference_tcp(const boost::asio::ip::tcp::endpoint & endpoint)
	:
	  c_peer_reference (c_peer_reference::type::e_tcp),
	  m_endpoint(endpoint)
{}

std::string c_peer_reference_tcp::to_string() const {
	std::ostringstream oss;
	oss << m_endpoint;
	return oss.str();
}

boost::asio::ip::tcp::endpoint c_peer_reference_tcp::get_endpoint() const noexcept{
	return m_endpoint;
}

bool c_peer_reference_tcp::operator<(const c_peer_reference & other) const noexcept {
	const c_peer_reference_tcp & other_tcp = dynamic_cast<const c_peer_reference_tcp &>(other);
	return m_endpoint < other_tcp.m_endpoint;
}

std::unique_ptr<c_peer_reference> c_peer_reference_tcp::clone() const {
	std::unique_ptr<c_peer_reference> copy = std::make_unique<c_peer_reference_tcp>(m_endpoint);
	return copy;
}

bool c_peer_reference_tcp::is_equal(const c_peer_reference & other) const {
	const auto other_peer_reference = dynamic_cast<const c_peer_reference_tcp&>(other);
	return (m_endpoint == other_peer_reference.m_endpoint);
}


////////////////////////////////////////////////////////////////////////////


c_peer_reference_url::c_peer_reference_url()
	:
	  c_peer_reference(c_peer_reference::type::e_url)
{
}

c_peer_reference_url::c_peer_reference_url(const boost::asio::ip::tcp::endpoint & endpoint)
	:
	  c_peer_reference (c_peer_reference::type::e_url),
	  m_endpoint(endpoint)
{}

std::string c_peer_reference_url::to_string() const {
	std::ostringstream oss;
	oss << m_endpoint;
	return oss.str();
}

boost::asio::ip::tcp::endpoint c_peer_reference_url::get_endpoint() const noexcept {
	return m_endpoint;
}

bool c_peer_reference_url::operator<(const c_peer_reference & other) const noexcept {
	const c_peer_reference_url & other_tcp = dynamic_cast<const c_peer_reference_url &>(other);
	return m_endpoint < other_tcp.m_endpoint;
}

std::unique_ptr<c_peer_reference> c_peer_reference_url::clone() const {
	std::unique_ptr<c_peer_reference> copy = std::make_unique<c_peer_reference_url>(m_endpoint);
	return copy;
}

bool c_peer_reference_url::is_equal(const c_peer_reference & other) const {
	const auto other_peer_reference = dynamic_cast<const c_peer_reference_url&>(other);
	return (m_endpoint == other_peer_reference.m_endpoint);
}

std::unique_ptr<c_peer_reference> c_peer_reference_tcp_creator::create_peer_reference(const std::string & address, unsigned short port) const {
	const auto ip = boost::asio::ip::make_address(address);
	return std::make_unique<c_peer_reference_tcp>(ip, port);
}

std::unique_ptr<c_peer_reference> c_peer_reference_url_creator::create_peer_reference(const std::string & address, unsigned short port) const {
	boost::asio::io_context io_context;
	boost::asio::ip::tcp::resolver resolver(io_context);
	boost::asio::ip::tcp::resolver::query query(address, std::to_string(port));
	boost::asio::ip::tcp::resolver::iterator it = resolver.resolve(query);
	return std::make_unique<c_peer_reference_url>(it->endpoint());
}

std::unique_ptr<c_peer_reference> create_peer_reference(const std::string & address, unsigned short port) {
	std::unique_ptr<c_peer_reference_creator> creator;
	boost::system::error_code ec;
	boost::asio::ip::make_address(address, ec);
	if(!ec) {
		creator = std::make_unique<c_peer_reference_tcp_creator>();
	} else {
		creator = std::make_unique<c_peer_reference_url_creator>();
	}
	return creator->create_peer_reference(address, port);
}
