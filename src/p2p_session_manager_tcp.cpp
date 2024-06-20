#include <shared_mutex>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include "logger.hpp"
#include "p2p_session_manager_tcp.hpp"

c_p2p_session_manager_tcp::c_p2p_session_manager_tcp(read_handler read_handler, new_peer_handler new_peer_handler, boost::asio::ip::tcp::endpoint listen_endpoint)
	:
	  c_p2p_session_manager (read_handler, new_peer_handler, listen_endpoint)
{
}

boost::asio::ip::tcp::socket c_p2p_session_manager_tcp::connect_to_peer(const c_peer_reference & peer_info) {
	LOG(debug)<<"connect to peer " << peer_info.to_string();
	boost::asio::ip::basic_endpoint<boost::asio::ip::tcp> endpoint;
	if(peer_info.get_type() == c_peer_reference::type::e_tcp) {
		const auto & peer_tcp = dynamic_cast<const c_peer_reference_tcp &>(peer_info);
		endpoint = peer_tcp.get_endpoint();
	} else if(peer_info.get_type() == c_peer_reference::type::e_url) {
		const auto & peer_tcp = dynamic_cast<const c_peer_reference_url &>(peer_info);
		endpoint = peer_tcp.get_endpoint();
	}
	auto & io_context = get_io_context();
	boost::asio::ip::tcp::socket connect_socket(io_context);
	const auto connect_future = connect_socket.async_connect(endpoint, boost::asio::use_future);
	const auto timeout = std::chrono::seconds(30);
	const auto status = connect_future.wait_for(timeout);
	if (status == std::future_status::timeout) {
		throw std::runtime_error("timeout");
	} else if (status == std::future_status::deferred) {
		throw std::runtime_error("future status == deferred");
	}
	return connect_socket;
}

std::unique_ptr<c_peer_reference> c_p2p_session_manager_tcp::get_accept_remote_peer_info(const boost::asio::ip::tcp::socket & socket) const {
	const auto remote_endpoint = socket.remote_endpoint();
	std::unique_ptr<c_peer_reference> peer_info = std::make_unique<c_peer_reference_tcp>(remote_endpoint);
	return peer_info;
}
