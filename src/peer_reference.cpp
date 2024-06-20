#include "peer_reference.hpp"
#include <sstream>
#include <iostream>
#include <sodium.h>
#include "logger.hpp"

std::atomic<size_t> c_peer_reference_onion::s_hidden_peer_number(0);

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



c_peer_reference_onion::c_peer_reference_onion()
	:
	  c_peer_reference(c_peer_reference::type::e_onion),
	  m_hidden_remote(true)
{
	create_password_and_username();
	const size_t peer_number = std::atomic_fetch_add(&s_hidden_peer_number, std::size_t{1});
	m_peer_name = "[hidden tor peer nr <" + std::to_string(peer_number) + ">]";
}

c_peer_reference_onion::c_peer_reference_onion(const std::string & address, unsigned short port)
	:
	  c_peer_reference(c_peer_reference::type::e_onion),
	  m_peer_name(address),
	  m_port(port),
	  m_hidden_remote(false)
{
	create_password_and_username();
	try {
		const std::string suffix(".onion");
		if (address.substr(address.size() - suffix.size()) != suffix) throw std::invalid_argument("no '.onion' suffix");
	} catch (const std::exception & e) {
		throw std::invalid_argument(address + " is a bad onion address: " + e.what());
	}
}

std::string c_peer_reference_onion::to_string() const {
	if (m_hidden_remote) LOG(debug)<<"cannot get onion address";
	return m_peer_name + ':' + std::to_string(m_port);
}

bool c_peer_reference_onion::is_hidden_remote() const noexcept {
	return m_hidden_remote;
}

std::string c_peer_reference_onion::get_onion_address() const {
	if (m_hidden_remote) throw std::runtime_error("cannot get onion address");
	return m_peer_name;
}

unsigned short c_peer_reference_onion::get_port() const{
	if (m_hidden_remote) throw std::runtime_error("cannot get port");
	return m_port;
}

bool c_peer_reference_onion::operator<(const c_peer_reference & other) const noexcept {
	const c_peer_reference_onion & other_onion = dynamic_cast<const c_peer_reference_onion &>(other);
	return m_peer_name < other_onion.m_peer_name;
}

std::unique_ptr<c_peer_reference> c_peer_reference_onion::clone() const {
	std::unique_ptr<c_peer_reference> copy = std::make_unique<c_peer_reference_onion>();
	c_peer_reference_onion & copy_ref = static_cast<c_peer_reference_onion &>(*copy);
	copy_ref.m_peer_name = m_peer_name;
	copy_ref.m_port = m_port;
	copy_ref.m_hidden_remote = m_hidden_remote;
	copy_ref.m_soks5_credentials = m_soks5_credentials;
	return copy;
}

tor_socks5_credentials c_peer_reference_onion::get_socks5_credentials() const {
	return m_soks5_credentials;
}

void c_peer_reference_onion::create_password_and_username() {
	this->m_soks5_credentials.m_username_soks5.resize(0xff);
	this->m_soks5_credentials.m_password_soks5.resize(0xff);
	auto generator = []() { char random_char = static_cast<char>(randombytes_uniform(0x100)); return random_char;};
	std::generate(m_soks5_credentials.m_username_soks5.begin(), m_soks5_credentials.m_username_soks5.end(), generator);
	std::generate(m_soks5_credentials.m_password_soks5.begin(), m_soks5_credentials.m_password_soks5.end(), generator);
}

bool c_peer_reference_onion::is_equal(const c_peer_reference & other) const {
	const auto other_peer_reference = dynamic_cast<const c_peer_reference_onion&>(other);
	if (m_peer_name != other_peer_reference.m_peer_name) return false;
	if (m_port != other_peer_reference.m_port) return false;
	return true;
}

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

std::unique_ptr<c_peer_reference> c_peer_reference_onion_creator::create_peer_reference(const std::string & address, unsigned short port) const {
	return std::make_unique<c_peer_reference_onion>(address, port);
}

std::unique_ptr<c_peer_reference> create_peer_reference(const std::string & address, unsigned short port) {
	std::unique_ptr<c_peer_reference_creator> creator;
	if (address.find(".onion") != std::string::npos) {
		creator = std::make_unique<c_peer_reference_onion_creator>();
	} else {
		boost::system::error_code ec;
		boost::asio::ip::make_address(address, ec);
		if(!ec) {
			creator = std::make_unique<c_peer_reference_tcp_creator>();
		} else {
			creator = std::make_unique<c_peer_reference_url_creator>();
		}
	}
	return creator->create_peer_reference(address, port);
}
