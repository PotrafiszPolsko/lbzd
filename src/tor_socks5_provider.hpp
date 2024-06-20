#ifndef C_TOR_SOCKS5_PROVIDER_HPP
#define C_TOR_SOCKS5_PROVIDER_HPP

#include <sodium/randombytes.h>
#include <type_traits>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <future>
#include "params.hpp"

struct tor_socks5_credentials;

namespace socks5 {
enum class command_type : std::underlying_type_t<std::byte> {
	connect = 0x01
};

struct tor_endpoint {
	std::string m_onion_address;
	unsigned short m_onion_port;
};

// REQUESTS

// rfc1929 - select the auth negotiation - 0x00 - noauth , 0x02 - user/pass
class request_auth_select {
	unsigned char m_version = (0x05);
	unsigned char m_n_methods = (0x02); // two method
	unsigned char m_method_no_auth = (0x00); // 0x00 - no authentication reqired
	unsigned char m_method_auth_up = (0x02); // 0x02 - proxy user/pass
public:
	std::array<boost::asio::const_buffer, 4> buffers() const {
		std::array<boost::asio::const_buffer, 4> bufs =
		{
		{
		boost::asio::buffer(&m_version, 1),
		boost::asio::buffer(&m_n_methods, 1),
		boost::asio::buffer(&m_method_no_auth, 1),
		boost::asio::buffer(&m_method_auth_up, 1)
		}
		};
		return bufs;
	}
};

// rfc1929 - request S5 U/P data
class request_auth_userpass {
	unsigned char m_version = (0x01);
	unsigned char m_u_len = (0xff);
	std::string m_username;
	unsigned char m_p_len = (0xff);
	std::string m_password;
public:
	request_auth_userpass() {
		m_username.resize(0xff);
		m_password.resize(0xff);
		auto generator = []() { auto random_char = static_cast<char>(randombytes_uniform(0x100)); return random_char; };
		std::generate(m_username.begin(), m_username.end(), generator);
		std::generate(m_password.begin(), m_password.end(), generator);
	}
	void set_username(const std::string & username) {
		if ((username.length() > 255) || (username.empty())) {
			throw std::invalid_argument("The username length has to be between <1-255>. RFC1929 Point No.2");
		}
		m_username = username;
	}
	void set_password(const std::string & password) {
		if ((password.length() > 255) || (password.empty())) {
			throw std::invalid_argument("The password length has to be between <1-255>. RFC1929 Point No.2");
		}
		m_password = password;
	}
	std::array<boost::asio::const_buffer, 5> buffers() const {
		std::array<boost::asio::const_buffer, 5> bufs =
		{
		{
		boost::asio::buffer(&m_version, sizeof(m_version)),
		boost::asio::buffer(&m_u_len, sizeof(m_u_len)),
		boost::asio::buffer(m_username),
		boost::asio::buffer(&m_p_len, sizeof(m_p_len)),
		boost::asio::buffer(m_password)
		}
		};
		return bufs;
	}
};

// rfc1928 - request with no auth
class request_auth_nouserpass {
	unsigned char m_version = (0x05);
	unsigned char m_n_methods = (0x01); // one method
	unsigned char m_method = (0x00);
public:
	std::array<boost::asio::const_buffer, 3> buffers() const {
		std::array<boost::asio::const_buffer, 3> bufs =
		{
		{
		boost::asio::buffer(&m_version, 1),
		boost::asio::buffer(&m_n_methods, 1),
		boost::asio::buffer(&m_method, 1)
		}
		};
		return bufs;
	}
};

// request to host
class request_connect {
private:
	const unsigned char m_version = (0x05);
	const command_type m_cmd = command_type::connect;
	const unsigned char m_reserved = (0x00);
	const unsigned char m_a_type = (0x03);
	const std::string m_destination_address;
	const uint8_t m_destination_address_size;
	const unsigned short m_port;

public:
	request_connect(const tor_endpoint& tor_endpoint)
	:
	m_destination_address(tor_endpoint.m_onion_address ),
	m_destination_address_size(static_cast<uint8_t>(m_destination_address.size())),
	m_port(htons(tor_endpoint.m_onion_port))
	{}

	std::array<boost::asio::const_buffer, 7> buffers() const{
		std::array<boost::asio::const_buffer, 7> bufs =
		{
		{
		boost::asio::buffer(&m_version, 1),
		boost::asio::buffer(&m_cmd, 1),
		boost::asio::buffer(&m_reserved, 1),
		boost::asio::buffer(&m_a_type, 1),
		boost::asio::buffer(&m_destination_address_size, 1),
		boost::asio::buffer(m_destination_address.data(), m_destination_address_size), // must be without '\0'
		boost::asio::buffer(&m_port, 2),
		}
		};
		return bufs;
	}
};

// RESPONSES

// rfc1929
class response_auth_select {
public:
	unsigned char m_version;
	unsigned char m_method; // xxx STATUS
	std::array<boost::asio::mutable_buffer, 2> buffers() {
		std::array<boost::asio::mutable_buffer, 2> bufs =
		{
		{
		boost::asio::buffer(&m_version, 1),
		boost::asio::buffer(&m_method, 1)
		}
		};
		return bufs;
	}
};

// rfc1928 - pkt.6
class response_connect {
public:
	unsigned char m_version;
	unsigned char m_rep;
	unsigned char m_reserved;
	unsigned char m_a_type;
	boost::asio::ip::address_v4::bytes_type m_address_bytes;
	unsigned short m_port;
	boost::asio::ip::address_v4 get_address() {
		return boost::asio::ip::address_v4(m_address_bytes);
	}

	std::array<boost::asio::mutable_buffer, 6> buffers() {
		std::array<boost::asio::mutable_buffer, 6> bufs =
		{
		{
		boost::asio::buffer(&m_version, 1),
		boost::asio::buffer(&m_rep, 1),
		boost::asio::buffer(&m_reserved, 1),
		boost::asio::buffer(&m_a_type, 1),
		boost::asio::buffer(m_address_bytes), // no reference beacuse m_address_bytes is an array
		boost::asio::buffer(&m_port, 2)
		}
		};
		return bufs;
	}
};
} // namespace

class c_tor_socks5_provider
{
public:
	c_tor_socks5_provider(boost::asio::io_context & ioservice,
                      unsigned short port_tor_socks5 = n_networkparams::default_port_tor_socks5);

	boost::asio::ip::tcp::socket connect_to_onion_address(const socks5::tor_endpoint & tor_endpoint,
											    const tor_socks5_credentials & tor_credentials,
											    const std::chrono::seconds & timeout);

private:
	void send_auth_select();
	void receive_auth_select();
	void send_auth_userpass(const tor_socks5_credentials & tor_credentials);
	void receive_auth_userpass();
	void request_connect(const socks5::tor_endpoint& tor_endpoint);
	void response_connect();
	void check_future_status(const std::future_status status);

	unsigned short m_onion_port;
	std::chrono::steady_clock::time_point m_timeout;
	boost::asio::ip::tcp::socket m_socket;
};

#endif // C_TOR_SOCKS5_PROVIDER_HPP
