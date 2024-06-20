#ifndef INCLUDE_rpc_server_hpp
#define INCLUDE_rpc_server_hpp

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include "nlohmann/json.hpp"
#include "rpc_exec.hpp"


/**
 * @brief Implements a server - does async_accept() or similar, spawns sessions
 */
class c_rpc_server_base {
	public:
		c_rpc_server_base(std::shared_ptr<c_rpc_exec> exec);
		virtual ~c_rpc_server_base()=default;
		virtual void run_and_block()=0; ///< starts processing the network, and BLOCKS - will return only when we are exiting e.g. from please_stop()
		std::shared_ptr<c_rpc_exec> get_exec(); ///< returns the exec object, e.g. to finish it's construction
	private:
		std::shared_ptr<c_rpc_exec> m_exec;
};

class session_rpc : public std::enable_shared_from_this<session_rpc> {
	public:
		using t_socket = boost::asio::ip::tcp::socket;
		session_rpc(std::shared_ptr<c_rpc_exec> exec, t_socket && sock, const std::string & auth_string);
		void start();
	private:
		std::string generate_response(const std::string & json_as_str);
		void do_read_handler(const boost::system::error_code & ec, size_t);
		bool check_auth_string(const std::string & auth_string_html) const;
		std::shared_ptr<c_rpc_exec> m_exec;
		boost::beast::http::request<boost::beast::http::string_body> m_reqest;
		boost::beast::http::response<boost::beast::http::string_body> m_response;
		boost::beast::flat_buffer m_buffer;
		boost::beast::tcp_stream m_stream;
		const std::string m_auth_string;
};

class c_rpc_server final : public c_rpc_server_base {
	public:
		using t_socket = boost::asio::ip::tcp::socket ;
		using t_endpoint = boost::asio::ip::tcp::endpoint;
		using t_acceptor = boost::asio::ip::tcp::acceptor;
		c_rpc_server(std::shared_ptr<c_rpc_exec> exec, t_endpoint endpoint, const std::string auth_string);
		void run_and_block() override;
	private:
		void do_accept();
		boost::asio::io_context m_service;
		t_acceptor m_acceptor;
		t_socket m_socket;
		const std::string m_auth_string;
};

#endif
