#include "session.hpp"
#include "logger.hpp"
#include "utils.hpp"

t_read_data::t_read_data()
	: m_read_size(s_read_size_buffer_size),
	  m_read_buffer_to_nonce(nonce_size)
{}

c_tcp_session::c_tcp_session(boost::asio::io_context & io_context, boost::asio::ip::tcp::socket && socket, std::unique_ptr<c_peer_reference> && peer_info)
	:
	  m_socket(std::move(socket)),
	  m_strand(io_context),
	  m_peer_info(std::move(peer_info)),
	  m_crypto()
{
	LOG(debug)<<"start new session: " << m_socket.local_endpoint() << " " << m_socket.remote_endpoint();
}

c_tcp_session::~c_tcp_session() {
	close_session();
}

void c_tcp_session::send(const std::string & msg) {
	std::lock_guard<std::mutex> lock(m_socket_mtx);
	c_crypto crypto = m_crypto;
	crypto.generate_nonce();
	const auto msg_encrypt = crypto.encrypt(msg);
	const uint32_t size = static_cast<uint32_t>(msg_encrypt.size());
	const auto write_size = get_array_byte(size);
	const auto nonce = crypto.get_nonce();
	std::vector<unsigned char> data_to_send;
	std::copy(write_size.cbegin(), write_size.cend(), std::back_inserter(data_to_send));
	std::copy(nonce.cbegin(), nonce.cend(), std::back_inserter(data_to_send));
	std::copy(msg_encrypt.cbegin(), msg_encrypt.cend(), std::back_inserter(data_to_send));
	LOG(debug) << "send size: " << data_to_send.size();
	assert(data_to_send.size() != 0);
	m_send_messages_queue.push(std::move(data_to_send));
	assert(m_send_messages_queue.size() > 0);
	if (m_send_messages_queue.size() == 1) {
		do_write();
	}
}

void c_tcp_session::async_read(read_handler handler) {
	// read size
	auto self(shared_from_this());
	std::lock_guard<std::mutex> lock(m_socket_mtx);
	t_read_data read_data;
	read_data.m_crypto = m_crypto;
	const auto buffer = boost::asio::buffer(read_data.m_read_size);
	boost::asio::async_read(
		m_socket, buffer,
		boost::asio::bind_executor(m_strand,
		[this, handler, self, read_data = std::move(read_data)](const boost::system::error_code & error, [[maybe_unused]] size_t bytes_transferred) mutable {
			if (error) {
				LOG(error) << error.message();
				close_session();
				return;
			}
			std::unique_lock<std::mutex> lock(m_socket_mtx);
			if (!m_socket.is_open()) {
				LOG(info) << "timeout, close session";
				close_session();
				return;
			}
			lock.unlock();
			const size_t buffer_size = get_integer<uint32_t>(read_data.m_read_size);
			if (buffer_size > m_max_input_read_bytes) {
				LOG(info) << "Read buffer size (" << buffer_size << "B) bigger than max allowed (" << m_max_input_read_bytes << "B)";
				close_session();
				return;
			}
			LOG(debug) << "start reading " << buffer_size << " bytes";
			assert(bytes_transferred == t_read_data::s_read_size_buffer_size);
			read_data.m_read_buffer.resize(buffer_size);
			async_read_to_buffer_nonce(handler, read_data);
		} // lambda
	) // strand
	);
}

void c_tcp_session::async_read_to_buffer(read_handler handler, t_read_data & read_data) {
	auto self(shared_from_this());
	std::lock_guard<std::mutex> lock(m_socket_mtx);
	const auto buffer = boost::asio::buffer(read_data.m_read_buffer.data(), read_data.m_read_buffer.size());
	boost::asio::async_read(
		m_socket, buffer,
		boost::asio::bind_executor(m_strand,
		[this, handler, self, read_data = std::move(read_data)](const boost::system::error_code & error, [[maybe_unused]] size_t bytes_transferred) {
			if (error) {
				LOG(error)<<error.message();
				close_session();
				return;
			}
			const size_t buffer_size = get_integer<uint32_t>(read_data.m_read_size);
			assert(bytes_transferred == buffer_size);
			assert(bytes_transferred == read_data.m_read_buffer.size());
			try {
				const auto msg_decrypt = read_data.m_crypto.decrypt(read_data.m_read_buffer);
				handler(*m_peer_info, span(msg_decrypt.data(), msg_decrypt.size()));
			} catch(const std::exception & exception) {
				LOG(error) << "Read handler error: " << exception.what();
				close_session();
				return;
			}
			
			LOG(debug)<<"continue reading";
			async_read(handler); // continue reading
		} // lambda
		) // strand
	);
}

void c_tcp_session::async_read_to_buffer_nonce(read_handler handler, t_read_data & read_data) {
	auto self(shared_from_this());
	std::lock_guard<std::mutex> lock(m_socket_mtx);
	const auto buffer = boost::asio::buffer(read_data.m_read_buffer_to_nonce.data(), read_data.m_read_buffer_to_nonce.size());
	boost::asio::async_read(
		m_socket, buffer,
		boost::asio::bind_executor(m_strand,
		[this, handler, self, read_data = std::move(read_data)](const boost::system::error_code & error, [[maybe_unused]] size_t bytes_transferred) mutable {
			if (error) {
				LOG(error)<<error.message();
				close_session();
				return;
			}
			assert(bytes_transferred == nonce_size);
			t_nonce_type nonce;
			std::copy(read_data.m_read_buffer_to_nonce.cbegin(), read_data.m_read_buffer_to_nonce.cend(), nonce.begin());
			read_data.m_crypto.set_nonce(nonce);
			LOG(debug)<<"continue reading";
			async_read_to_buffer(handler, read_data);
		} // lambda
		) // strand
	);
}

std::unique_ptr<c_peer_reference> c_tcp_session::get_peer_info() const {
	return m_peer_info->clone();
}

void c_tcp_session::send_dh_key_to_client() {
	c_dh dhpk;
	const auto pk = dhpk.pk();
	std::unique_lock<std::mutex> lock(m_socket_mtx);
	auto future = boost::asio::async_write(m_socket, boost::asio::buffer(pk), boost::asio::use_future);
	auto future_status = future.wait_for(std::chrono::seconds(30));
	if (future_status == std::future_status::timeout) throw std::runtime_error("write dh key timeout");
	std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> pk_srv;
	future = boost::asio::async_read(m_socket, boost::asio::buffer(pk_srv), boost::asio::use_future);
	future_status = future.wait_for(std::chrono::seconds(30));
	if (future_status == std::future_status::timeout) throw std::runtime_error("read dh key timeout");
	auto keyserv = dhpk.generate_for_client(pk_srv);
	t_nonce_type nonce;
	future = boost::asio::async_read(m_socket, boost::asio::buffer(nonce), boost::asio::use_future);
	future_status = future.wait_for(std::chrono::seconds(30));
	if (future_status == std::future_status::timeout) throw std::runtime_error("read nonce timeout");
	lock.unlock();
	m_crypto.set_dh_keys(keyserv);
	m_crypto.set_nonce(nonce);
}

void c_tcp_session::send_dh_key_to_server() {
	c_dh dhpk;
	const auto pk = dhpk.pk();
	std::lock_guard<std::mutex> lock(m_socket_mtx);
	boost::asio::write(m_socket, boost::asio::buffer(pk));
	std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> pk_cli;
	boost::asio::read(m_socket, boost::asio::buffer(pk_cli));
	auto keyserv = dhpk.generate_for_server(pk_cli);
	m_crypto.generate_nonce();
	const auto nonce = m_crypto.get_nonce();
	m_crypto.set_dh_keys(keyserv);
	boost::asio::write(m_socket, boost::asio::buffer(nonce));
}

void c_tcp_session::start(read_handler handler) {
	async_read(handler);
}

void c_tcp_session::close_session() {
	LOG(debug) << "Close TCP session";
	boost::system::error_code ec;
	m_socket.cancel(ec); // cancel all asynchronous operations associated with the socket
	m_socket.close(ec);
	if (ec) {
		LOG(warning) << "We have error on close session, but flag close is set to true anyway : " << ec.message();
	}
	if (ec) {
		LOG(warning) << "deadline_timer.close() error: " << ec.message();
	}
}

void c_tcp_session::do_write() {
	const auto buffer = boost::asio::buffer(m_send_messages_queue.front());
	auto self(shared_from_this());
	boost::asio::async_write(
			m_socket,
			buffer,
			boost::asio::bind_executor(m_strand,
			[this, self](const boost::system::error_code & error, size_t size) {
				if (error) {
					LOG(error) << error.message();
					close_session();
					return;
				}
				LOG(debug) << "Send " << size << " bytes";

				std::unique_lock<std::mutex> lock(m_socket_mtx);
				m_send_messages_queue.pop();
				if (!m_socket.is_open()) {
					LOG(info) << "timeout, close session";
					close_session();
					return;
				}
				if (m_send_messages_queue.size() > 0) do_write();
				lock.unlock();
			} // lambda
		) // strand
	);
}
