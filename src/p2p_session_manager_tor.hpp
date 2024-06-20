#ifndef C_P2P_SESSION_MANAGER_TOR_HPP
#define C_P2P_SESSION_MANAGER_TOR_HPP

#include <shared_mutex>
#include <filesystem>
#include "session.hpp"
#include "p2p_session_manager.hpp"
#include "tor_control.hpp"

class c_p2p_session_manager_tor : public c_p2p_session_manager {
	public:
		c_p2p_session_manager_tor(read_handler read_handler, new_peer_handler new_peer_handler, unsigned short hidden_service_port, const std::filesystem::path & datadir_path,
								  unsigned short socks5_port, unsigned short control_port);
		~c_p2p_session_manager_tor() override = default;
		void new_identity();
		virtual std::string get_tor_address() const;
		boost::asio::ip::tcp::socket connect_to_peer(const c_peer_reference & peer_info) override;
		virtual unsigned short get_hidden_service_port() const;
	protected:
		std::unique_ptr<c_peer_reference> get_accept_remote_peer_info(const boost::asio::ip::tcp::socket & socket) const override;
	private:
		void open_hidden_service(unsigned short port, const std::string & directory);
		std::string read_tor_address(unsigned short hidden_service_port, const std::filesystem::path & datadir_path);
		const unsigned short m_socks5_port;
		const unsigned short m_control_port;
		const unsigned short m_hidden_service_port;

		c_tor_control m_tor_control;
		std::string m_tor_address;
};

#endif // C_P2P_SESSION_MANAGER_TOR_HPP
