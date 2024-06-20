#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/randombytes.h>
#include <sodium/utils.h>
#include <boost/asio/read_until.hpp>
#include <boost/asio/write.hpp>
#include <iostream>
#include <fstream>
#include "tor_control.hpp"
#include "utils-node.hpp"
#include "logger.hpp"

c_tor_control::c_tor_control(unsigned short control_port)
	:
	  m_tor_control_socket(m_io_service)
{
	boost::system::error_code ec;
	m_tor_control_socket.connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), control_port), ec);
	if(ec) {
		LOG(error)<<"Error : " << ec.message();
		throw(std::runtime_error("Cannot connect to tor control port! The program will not be executed!"));
	}
	m_client_nonce_bin.fill(0);
	m_cookie_value_bin.fill(0);
	m_server_nonce_bin.fill(0);
	generate_client_nonce();
}

std::string c_tor_control::open_hidden_service(const std::string & tor_request) {
	std::string onion_address = get_onion_address(tor_request);
	m_tor_key = get_onion_secret_key();
	get_ok_status();
	return onion_address;
}

std::string c_tor_control::open_hidden_service_with_sending_sk(const std::string & tor_request) {
	std::string onion_address = get_onion_address(tor_request);
	get_ok_status();
	return onion_address;
}

void c_tor_control::new_identity() {
	const std::string cmd ="signal NEWNYM\r\n";
	send_command_to_tor(cmd);
}

void c_tor_control::authorize() {
	get_protocol_info();
	get_auth_method();
	get_tor_version();
	get_ok_status();
	get_authchallenge();
	get_authenticate();
}

std::string c_tor_control::read_tor_address(unsigned short hidden_service_port, const std::filesystem::path &datadir_path) {
	const std::string port_as_str = std::to_string(hidden_service_port);
	const auto path_to_the_tor_key_file = datadir_path / n_utils_node::name_of_the_file_tor_key;
	if(!std::filesystem::exists(path_to_the_tor_key_file)){
		const std::string tor_request = "ADD_ONION NEW:ED25519-V3 Port=" + port_as_str + ",127.0.0.1:" + port_as_str;
		const auto tor_address = open_hidden_service(tor_request);
		const auto tor_key = get_tor_key();
		make_tor_key_file(tor_key, datadir_path);
		return tor_address;
	}
	const auto tor_key = get_tor_key_from_file(datadir_path);
	const std::string tor_request = "ADD_ONION ED25519-V3:" + tor_key + " Port=" + port_as_str + ",127.0.0.1:" + port_as_str;
	const auto tor_address = open_hidden_service_with_sending_sk(tor_request);
	return tor_address;
}

void c_tor_control::generate_client_nonce() {
	randombytes_buf(m_client_nonce_bin.data(), m_client_nonce_bin.size());
	m_client_nonce_hex.resize(65);
	sodium_bin2hex(&m_client_nonce_hex[0], m_client_nonce_hex.size(),m_client_nonce_bin.data(),m_client_nonce_bin.size());
	m_client_nonce_hex.pop_back();
}

void c_tor_control::get_cookie_value_from_file(const std::string &cookie_file_path) {
	std::ifstream cookie_file;
	cookie_file.open(cookie_file_path, std::ios::binary | std::ios::in);
	cookie_file.read(reinterpret_cast<char*>(m_cookie_value_bin.data()), m_cookie_value_bin.size());
	cookie_file.close();
}

std::string c_tor_control::read_from_socket() {
	boost::system::error_code ec;
	const size_t bytes_transfered = read_until(m_tor_control_socket, m_read_buffer, m_delimiter, ec);
	if (ec) throw std::runtime_error("Read from tor control error: " + ec.message());
	boost::asio::const_buffer buffer_data = m_read_buffer.data();
	auto tor_buffer_answer = std::string(
		boost::asio::buffers_begin(buffer_data),
		boost::asio::buffers_begin(buffer_data) + bytes_transfered - m_delimiter.size());
	tor_buffer_answer += '\0';
	m_read_buffer.consume(bytes_transfered);
	return tor_buffer_answer;
}

std::string c_tor_control::get_protocol_info() {
	std::string protocol_info = "PROTOCOLINFO 1" + m_delimiter;
	m_tor_control_socket.send(boost::asio::buffer(protocol_info));
	return read_from_socket();
}

std::string c_tor_control::get_auth_method() {
	std::string tor_response = read_from_socket();
	get_cookie_file_path(tor_response);
	get_cookie_value_from_file(m_cookie_file_path);
	return tor_response;
}

std::string c_tor_control::get_tor_version() {
	return read_from_socket();
}

void c_tor_control::get_ok_status() {
	read_from_socket();
}

std::string c_tor_control::get_authchallenge() {
	std::string authchallange = "AUTHCHALLENGE SAFECOOKIE " + m_client_nonce_hex + m_delimiter;
	m_tor_control_socket.send(boost::asio::buffer(authchallange));
	std::string tor_response = read_from_socket();
	parse_auth_challange(tor_response);
	return tor_response;
}

void c_tor_control::get_cookie_file_path(const std::string &tor_read) {
	const std::string cookiefile = "COOKIEFILE=";
	auto cookiefile_location = tor_read.find(cookiefile) + cookiefile.length();
	m_cookie_file_path = tor_read.substr(cookiefile_location);
	std::remove(m_cookie_file_path.begin(), m_cookie_file_path.end(), '"');
}

void c_tor_control::parse_auth_challange(const std::string &tor_response) {
	const std::string serverhash = "SERVERHASH=";
	const std::string servernonce = "SERVERNONCE=";
	auto servernonce_location = tor_response.find(servernonce) + servernonce.length();
	m_server_nonce_hex = tor_response.substr(servernonce_location, 64);
	size_t adress_size;
	const auto ret = sodium_hex2bin(m_server_nonce_bin.data(), m_server_nonce_bin.size(), m_server_nonce_hex.data(), m_server_nonce_hex.size(), nullptr, &adress_size, nullptr);
	if (ret!=0) throw std::runtime_error("hex2bin error");
}

std::string c_tor_control::get_authenticate() {
	std::string authenticate = "AUTHENTICATE " + authenticate_line() + m_delimiter;
	m_tor_control_socket.send(boost::asio::buffer(authenticate));
	return read_from_socket();
}

std::string c_tor_control::authenticate_line() {
	std::array<unsigned char, crypto_auth_hmacsha256_BYTES> compute_hash;
	crypto_auth_hmacsha256_state state;
	crypto_auth_hmacsha256_init(&state, reinterpret_cast<const unsigned char*>(m_tor_client_auth_message.data()), m_tor_client_auth_message.size() );
	crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char*>(m_cookie_value_bin.data()), m_cookie_value_bin.size());
	crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char*>(m_client_nonce_bin.data()), m_client_nonce_bin.size());
	crypto_auth_hmacsha256_update(&state, reinterpret_cast<const unsigned char*>(m_server_nonce_bin.data()), m_server_nonce_bin.size());
	crypto_auth_hmacsha256_final(&state, compute_hash.data());
	std::string hex;
	hex.resize(compute_hash.size()*2+1);
	sodium_bin2hex(&hex[0], hex.size(), compute_hash.data() , compute_hash.size());
	hex.pop_back();
	return hex;
}

std::string c_tor_control::get_onion_address(const std::string & tor_request) {
	const std::string request = tor_request + m_delimiter;
	m_tor_control_socket.send(boost::asio::buffer(request));
	const std::string input_line = read_from_socket();
	const std::string line_prefix = "250-ServiceID=";
	if ( input_line.size() > 0 ) {
		std::string onion_address = input_line.substr(line_prefix.size());
		// remove "\n\r"
		onion_address.pop_back();
		onion_address.pop_back();
		onion_address += ".onion";
		return onion_address;
	}
	return "";
}

std::string c_tor_control::get_onion_secret_key() {
	const auto response_secret_key = read_from_socket();
	const std::string find_string = "ED25519-V3:";
	const auto pos = response_secret_key.find(find_string);
	if(pos==std::string::npos) throw std::runtime_error("Something wrong with the response about the secret key");
	const auto tor_key_tmp = response_secret_key.substr(pos+find_string.size());
	const auto tor_key = tor_key_tmp.substr(0, tor_key_tmp.size() - m_delimiter.size());
	return tor_key;
}

void c_tor_control::send_command_to_tor(const std::string &cmd) {
	boost::asio::write(m_tor_control_socket, boost::asio::buffer(cmd));
	LOG(debug)<<"start reading response";
	std::string response = read_from_socket();
	LOG(debug)<<"response: " << response;
	if (response.find("250 OK") == std::string::npos) // 250 OK\r\n
		throw std::runtime_error("Error in send command to tor : " + response);
}

std::string c_tor_control::get_tor_key() const {
	return m_tor_key;
}

std::string c_tor_control::get_tor_key_from_file(const std::filesystem::path &datadir_path) const {
	const auto path_to_the_tor_key_file = datadir_path / n_utils_node::name_of_the_file_tor_key;
	return n_utils_node::reading_string_to_a_file(path_to_the_tor_key_file);
}

std::filesystem::path c_tor_control::make_tor_key_file(const std::string & tor_key, const std::filesystem::path & datadir_path) const {
	const auto path_to_the_tor_key_file = datadir_path / n_utils_node::name_of_the_file_tor_key;
	return n_utils_node::make_file(path_to_the_tor_key_file, tor_key);
}
