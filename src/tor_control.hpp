#ifndef TOR_CONTROL_HPP
#define TOR_CONTROL_HPP

#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/streambuf.hpp>
#include <filesystem>
#include "params.hpp"

class c_tor_control {
	public:
		c_tor_control(const unsigned short control_port = n_networkparams::default_port_tor_control);
		std::string open_hidden_service(const std::string & tor_request); ///< open new hidden service and forward 127.0.0.0:port. The method returns new tor address.
		std::string open_hidden_service_with_sending_sk(const std::string & tor_request); ///< open new hidden service and forward 127.0.0.0:port.
		///The method returns the same tor address by sending the secret key to the tor server.
		///The tor address is associated with the secret key.
		void new_identity();
		void authorize();
		std::string read_tor_address(unsigned short hidden_service_port, const std::filesystem::path & datadir_path);
	private:
		std::string m_tor_key;
		boost::asio::io_service m_io_service;
		boost::asio::ip::tcp::socket m_tor_control_socket;
		boost::asio::streambuf m_read_buffer;
		std::string m_cookie_file_path;
		std::string m_client_nonce_hex;
		std::array<unsigned char , 32> m_client_nonce_bin;
		std::array<unsigned char , 32> m_cookie_value_bin;
		std::string m_server_nonce_hex;
		std::array<unsigned char , 32> m_server_nonce_bin;
		const std::string m_tor_client_auth_message = "Tor safe cookie authentication controller-to-server hash";
		const std::string m_delimiter = "\r\n";

		void generate_client_nonce();
		void get_cookie_value_from_file(const std::string & cookie_file_path);
		std::string read_from_socket();
		std::string get_protocol_info();
		std::string get_auth_method();
		std::string get_tor_version();
		void get_ok_status();
		std::string get_authchallenge();
		void get_cookie_file_path(const std::string & tor_read);
		void parse_auth_challange(const std::string & tor_response);
		std::string get_authenticate();
		std::string authenticate_line();
		std::string get_onion_address(const std::string & tor_request);
		std::string get_onion_secret_key();
		void send_command_to_tor(const std::string & cmd);
		std::string get_tor_key_from_file(const std::filesystem::path & datadir_path) const;
		std::string get_tor_key() const;
		std::filesystem::path make_tor_key_file(const std::string & tor_key, const std::filesystem::path & datadir_path) const;
};

#endif // TOR_CONTROL_HPP
