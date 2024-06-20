#include "p2p_session_manager.hpp"
#include "logger.hpp"

c_p2p_session_manager::c_p2p_session_manager(read_handler read_handler, new_peer_handler new_peer_handler, boost::asio::ip::tcp::endpoint listen_endpoint)
	:
	  m_sessions_mtx(),
	  m_sessions(),
	  m_read_handler(read_handler),
	  m_new_peer_handler(new_peer_handler),
	  m_io_context(),
	  m_accept_socket(m_io_context),
	  m_acceptor(m_io_context, listen_endpoint)
{
	boost::asio::socket_base::reuse_address option(true);
	m_acceptor.set_option(option);
	do_accept();
	const auto number_of_threads = 1;
	for(int i = 0; i < number_of_threads; i++)
		m_io_context_thread.emplace_back(std::thread([this]{m_io_context.run();}));
}

c_p2p_session_manager::~c_p2p_session_manager() {
	m_io_context.stop();
	for(auto & thread : m_io_context_thread) {
		if (thread.joinable()) thread.join();
	}
}

void c_p2p_session_manager::add_peer(const c_peer_reference & peer_info) {
	std::unique_lock<std::shared_mutex> lock(m_sessions_mtx);
	remove_closed_sessions();
	if (m_sessions.size() >= s_connection_limit) {
		LOG(debug) << "Connected peer limit reached";
		return;
	}
	const auto peer_connected = std::any_of(
				m_sessions.cbegin(),
				m_sessions.cend(),
				[&peer_info](const std::weak_ptr<c_tcp_session> & session) {
					auto session_shared_ptr = session.lock();
					if (!session_shared_ptr) return false;
					const auto session_peer_info = session_shared_ptr->get_peer_info();
					return (*session_peer_info == peer_info);
				}
	);
	if (peer_connected) {
		LOG(debug) << "Peer already connected";
		return;
	}
	auto socket = connect_to_peer(peer_info);
	auto peer_info_copy = peer_info.clone();
	add_peer(std::move(peer_info_copy), std::move(socket), false);
	lock.unlock();
	m_new_peer_handler(peer_info);
}

auto c_p2p_session_manager::get_iterator_to_session(const c_peer_reference & peer_info) {
	remove_closed_sessions();
	auto session_iterator = std::find_if(
						  m_sessions.begin(),
						  m_sessions.end(),
						  [&peer_info](const std::weak_ptr<c_tcp_session> & session){
								auto session_shared_ptr = session.lock();
								if (!session_shared_ptr) return false;
								return (peer_info == (*session_shared_ptr->get_peer_info()));
						  }
						);
	if (session_iterator == m_sessions.end()) throw std::runtime_error("Not found peer " + peer_info.to_string());
	return session_iterator;
}

void c_p2p_session_manager::do_accept() {
	LOG(debug) << "Wait for new connection";
	m_acceptor.async_accept(m_accept_socket,
		[this](boost::system::error_code ec) {
			try {
				std::lock_guard<std::shared_mutex> lock(m_sessions_mtx);
				remove_closed_sessions();
				if (m_sessions.size() >= s_connection_limit) {
					LOG(debug) << "Connected peer limit reached";
					do_accept();
				}
				if (!ec) {
					auto remote_peer_info = get_accept_remote_peer_info(m_accept_socket);
					LOG(debug) << "new connection " << remote_peer_info->to_string();
					add_peer(std::move(remote_peer_info), std::move(m_accept_socket), true);
				} else {
					LOG(error) << "Accept error: " << ec.message();
				}
			} catch(const std::exception & e) {
				LOG(error) << "Accept error: " << e.what();
			}
			do_accept();
		}
	);
}

void c_p2p_session_manager::remove_closed_sessions() {
	m_sessions.erase(
				std::remove_if(m_sessions.begin(),
				               m_sessions.end(),
				               [](const std::weak_ptr<c_tcp_session> &ptr){return ptr.expired();}),
				m_sessions.end()
	);
}

void c_p2p_session_manager::remove_all_sessions() {
	std::lock_guard<std::shared_mutex> lock(m_sessions_mtx);
	m_sessions.clear();
}

void c_p2p_session_manager::async_read(const c_peer_reference & peer_info, read_handler handler) {
	std::lock_guard<std::shared_mutex> lock(m_sessions_mtx);
	const auto session_it = get_iterator_to_session(peer_info);
	auto session_shared_ptr = session_it->lock();
	if (!session_shared_ptr) {
		LOG(debug)<<"Connection is closed";
		delete_session(peer_info);
		return;
	}
	session_shared_ptr->async_read(handler);
}

void c_p2p_session_manager::send_to_peer(const c_peer_reference & peer_info, const std::string & msg) {
	LOG(debug)<<"send message to peer " << peer_info.to_string();
	std::lock_guard<std::shared_mutex> lock(m_sessions_mtx);
	const auto session_it = get_iterator_to_session(peer_info);
	auto session_shared_ptr = session_it->lock();
	if (!session_shared_ptr) {
		LOG(debug)<<"Connection is closed";
		delete_session(peer_info);
		return;
	}
	try {
		session_shared_ptr->send(msg);
	} catch (const std::exception & e) {
		LOG(error) << e.what();
		delete_session(peer_info);
		throw;
	}
}

void c_p2p_session_manager::send_to_all_peers(const std::string & msg) {
	// no lock here
	// get_peer_list and send_to_peer methods are thread safe
	const auto peer_list = get_peer_list();
	for (auto & peer : peer_list)
		send_to_peer(*peer, msg);
}

std::vector<std::unique_ptr<c_peer_reference> > c_p2p_session_manager::get_peer_list() {
	std::vector<std::unique_ptr<c_peer_reference>> peer_list;
	std::lock_guard<std::shared_mutex> lock(m_sessions_mtx);
	remove_closed_sessions();
	for (const auto & session : m_sessions) {
		auto session_shared_ptr = session.lock();
		if(session_shared_ptr) {
			assert(session_shared_ptr->get_peer_info() != nullptr);
			peer_list.push_back(session_shared_ptr->get_peer_info());
		}
	}
	return peer_list;
}

size_t c_p2p_session_manager::number_of_connected_peers() const {
	std::shared_lock<std::shared_mutex> lock(m_sessions_mtx);
	return m_sessions.size();
}

void c_p2p_session_manager::add_peer(std::unique_ptr<c_peer_reference> && peer_info, boost::asio::ip::tcp::socket && connected_socket, bool is_server) {
	auto session = std::make_shared<c_tcp_session>(m_io_context, std::move(connected_socket), std::move(peer_info));
	if(is_server) session->send_dh_key_to_server();
	else session->send_dh_key_to_client();
	session->start(m_read_handler); // start reading
	m_sessions.emplace_back(session);
}

boost::asio::io_context &c_p2p_session_manager::get_io_context() {
	return m_io_context;
}

void c_p2p_session_manager::delete_session(const c_peer_reference & peer_info) {
	// no lock here, m_sessions_mtx must be locked by caller (for avoid deadlocks)
	m_sessions.erase(
				std::remove_if(
					m_sessions.begin(),
					m_sessions.end(),
					[&peer_info](std::weak_ptr<c_tcp_session> & session) {
						auto session_shared_ptr = session.lock();
						if (!session_shared_ptr) return true; // no object under pointer so remove expired element
						return (peer_info == (*session_shared_ptr->get_peer_info()));
					}
				),
			m_sessions.end()
	);
}
