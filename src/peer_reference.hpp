#ifndef PEER_REFERENCE_HPP
#define PEER_REFERENCE_HPP

#include <string>
#include <vector>
#include <boost/asio/ip/tcp.hpp>
#include "tor_socks5_credentials.hpp"
#include <atomic>

class c_peer_reference {
	public:
		enum class type : uint8_t {e_tcp = 0, e_onion = 1, e_url = 2};
		c_peer_reference(type type);
		type get_type() const;
		virtual ~c_peer_reference() = default;
		virtual std::string to_string() const = 0;
		bool operator==(const c_peer_reference & other) const noexcept;
		virtual bool operator<(const c_peer_reference & other) const noexcept;
		virtual std::unique_ptr<c_peer_reference> clone() const = 0;
	private:
		// based on https://stackoverflow.com/a/29382957
		// A pure virtual function derived classes must implement.
		// Furthermore, this function has a precondition that it will only
		// be called when the 'other' is the same type as the instance
		// invoking the function.
		virtual bool is_equal(const c_peer_reference & other) const = 0;
		type m_type;
};

class c_peer_reference_tcp : public c_peer_reference {
	public:
		c_peer_reference_tcp();
		c_peer_reference_tcp(const boost::asio::ip::address & address, unsigned short port);
		c_peer_reference_tcp(const boost::asio::ip::tcp::endpoint & endpoint);
		std::string to_string() const override;
		boost::asio::ip::tcp::endpoint get_endpoint() const noexcept;
		bool operator<(const c_peer_reference & other) const noexcept override;
		std::unique_ptr<c_peer_reference> clone() const override;
	private:
		bool is_equal(const c_peer_reference & other) const override;
		boost::asio::ip::tcp::endpoint m_endpoint;
};

class c_peer_reference_url : public c_peer_reference {
	public:
		c_peer_reference_url();
		c_peer_reference_url(const boost::asio::ip::tcp::endpoint & endpoint);
		std::string to_string() const override;
		boost::asio::ip::tcp::endpoint get_endpoint() const noexcept;
		bool operator<(const c_peer_reference & other) const noexcept override;
		std::unique_ptr<c_peer_reference> clone() const override;
	private:
		bool is_equal(const c_peer_reference & other) const override;
		boost::asio::ip::tcp::endpoint m_endpoint;
};

class c_peer_reference_onion : public c_peer_reference {
	public:
		c_peer_reference_onion();
		c_peer_reference_onion(const std::string & address, unsigned short port);
		std::string to_string() const override;
		bool is_hidden_remote() const noexcept;
		std::string get_onion_address() const;
		unsigned short get_port() const;
		bool operator<(const c_peer_reference &other) const noexcept override;
		std::unique_ptr<c_peer_reference> clone() const override;
		tor_socks5_credentials get_socks5_credentials() const;
	private:
		std::string m_peer_name;
		unsigned short m_port;
		bool m_hidden_remote; ///< false for .onion addresses
		static std::atomic<size_t> s_hidden_peer_number;
		tor_socks5_credentials m_soks5_credentials;
		void create_password_and_username();
		bool is_equal(const c_peer_reference & other) const override;
};

class c_peer_reference_creator {
	public:
		virtual ~c_peer_reference_creator() = default;
		virtual std::unique_ptr<c_peer_reference> create_peer_reference(const std::string & address, unsigned short port) const = 0;
};

class c_peer_reference_tcp_creator : public c_peer_reference_creator {
	public:
		std::unique_ptr<c_peer_reference> create_peer_reference(const std::string & address, unsigned short port) const override;
};

class c_peer_reference_url_creator : public c_peer_reference_creator {
	public:
		std::unique_ptr<c_peer_reference> create_peer_reference(const std::string & address, unsigned short port) const override;
};

class c_peer_reference_onion_creator : public c_peer_reference_creator {
	public:
		std::unique_ptr<c_peer_reference> create_peer_reference(const std::string & address, unsigned short port) const override;
};

std::unique_ptr<c_peer_reference> create_peer_reference(const std::string & address, unsigned short port);

#endif // PEER_REFERENCE_HPP
