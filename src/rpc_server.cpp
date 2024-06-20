#include <iostream>
#include "rpc_server.hpp"
#include "logger.hpp"

using namespace std::string_literals;

session_rpc::session_rpc(std::shared_ptr<c_rpc_exec> exec , t_socket && sock, const std::string & auth_string)
	  :
	  m_exec( exec )
	  ,m_buffer(1024)
	  ,m_stream(std::move(sock)),
	  m_auth_string(auth_string)
{
}

void session_rpc::start() {
	auto self(this->shared_from_this());
	m_reqest = {};
	boost::beast::http::async_read(
				m_stream,
				m_buffer,
				m_reqest,
				[this, self](const boost::system::error_code & ec, size_t bytes_transferred) {
					do_read_handler(ec, bytes_transferred);
				}
	);
}

std::string session_rpc::generate_response(const std::string & json_as_str) {
	const auto json_input = nlohmann::json::parse(json_as_str);
	LOG(info) << "read json " << json_input.dump();
	std::vector<nlohmann::json> json_requests;
	if (json_input.is_array()) {
		for (const auto & json : json_input) json_requests.push_back(json);
	} else json_requests.push_back(json_input);
	std::vector<nlohmann::json> json_responses;
	for (const auto & json : json_requests) {
		try {
			json_responses.push_back(m_exec->execute( json ));
		} catch (const std::exception & exception) {
			nlohmann::json error_json;
			error_json["message"] = "Excpetion: "s + exception.what();
			json_responses.push_back(std::move(error_json));
		}
	}
	if (json_responses.size() == 1) return json_responses.front().dump();
	else {
		nlohmann::json batch_json;
		for (const auto & response : json_responses) batch_json.push_back(response);
		return batch_json.dump();
	}
}

void session_rpc::do_read_handler(const boost::system::error_code & ec, size_t) {
	if (ec) {
		LOG(error) << "RPC read handler error "<< ec.message();
		return;
	}
	boost::beast::http::response<boost::beast::http::string_body> response;
	response.set(boost::beast::http::field::content_type, "application/json");
	response.set(boost::beast::http::field::connection, "close");
	const auto authorization_string = std::string(m_reqest.base()["Authorization"]);
	if (!check_auth_string(authorization_string)) {
		response.result(401);
	} else {
		try {
			response.body() = generate_response(m_reqest.body());
		} catch (const std::exception & exception) {
			LOG(error) << "Wrong RPC format" << exception.what();
			response.body() = exception.what();
		}
	}
	response.prepare_payload();
	boost::beast::http::write(m_stream, response);
}

bool session_rpc::check_auth_string(const std::string & auth_string_html) const {
	std::string base64_auth_string;
	{
		std::stringstream ss(auth_string_html);
		ss >> base64_auth_string; // base64_auth_string == "Basic"
		ss >> base64_auth_string; // base64_auth_string == "WFhYOllZWQ=="
	}
	if (base64_auth_string == m_auth_string) return true;
	else return false;
}

c_rpc_server_base::c_rpc_server_base(std::shared_ptr<c_rpc_exec> exec)
: m_exec(exec)
{ }

std::shared_ptr<c_rpc_exec> c_rpc_server_base::get_exec() { return m_exec; }

c_rpc_server::c_rpc_server(std::shared_ptr<c_rpc_exec> exec, t_endpoint endpoint, const std::string auth_string)
	:
	  c_rpc_server_base(exec),
	  m_service(),
	  m_acceptor(m_service),
	  m_socket(m_service),
	m_auth_string(auth_string)
{
	m_acceptor.open(endpoint.protocol());
	m_acceptor.bind(endpoint);
	boost::asio::socket_base::reuse_address option(true);
	m_acceptor.set_option(option);
	m_acceptor.listen(boost::asio::socket_base::max_connections);
}

void c_rpc_server::run_and_block() {
	this->do_accept();
	m_service.run();
}

void c_rpc_server::do_accept() {
	m_acceptor.async_accept(m_socket, [this](const boost::system::error_code & ec) {
	if (ec) {
		LOG(error) << "RPC error "<< ec.message();
		return;
	}
	auto exec = get_exec();
	auto new_session = std::make_shared<session_rpc>(exec, std::move(m_socket), m_auth_string);
	new_session->start();
	do_accept();
	});
}
