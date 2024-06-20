#ifndef SESSION_HPP
#define SESSION_HPP

#include <boost/asio.hpp>
#include <memory>
#include <array>
#include <vector>
#include <queue>
#include "peer_reference.hpp"
#include "p2p_handler_types.hpp"
#include "crypto.hpp"
#include "dh.hpp"

class c_p2p_session_manager;

struct t_read_data {
	static constexpr size_t s_read_size_buffer_size = 4;
	std::vector<unsigned char> m_read_size;
	std::vector<unsigned char> m_read_buffer_to_nonce;
	std::vector<unsigned char> m_read_buffer;
	c_crypto m_crypto; // needed for decrypt
	t_read_data();
};

class c_tcp_session : public std::enable_shared_from_this<c_tcp_session> {
	public:
		c_tcp_session(boost::asio::io_context & io_context, boost::asio::ip::tcp::socket && socket, std::unique_ptr<c_peer_reference> && peer_info);
		~c_tcp_session();
		void send(const std::string & msg);
		void async_read(read_handler handler);
		std::unique_ptr<c_peer_reference> get_peer_info() const;
		void send_dh_key_to_client();
		void send_dh_key_to_server();
		void start(read_handler handler);
	private:
		boost::asio::ip::tcp::socket m_socket;
		std::mutex m_socket_mtx;
		boost::asio::io_context::strand m_strand;
		const std::unique_ptr<c_peer_reference> m_peer_info;
		c_crypto m_crypto;
		std::queue<std::vector<unsigned char>> m_send_messages_queue;
		const size_t m_max_input_read_bytes = 50 * 1024 * 1024;
		void close_session();
		void do_write();
		void async_read_to_buffer_nonce(read_handler handler, t_read_data & read_data);
		void async_read_to_buffer(read_handler handler, t_read_data & read_data);
};


#endif // SESSION_HPP
