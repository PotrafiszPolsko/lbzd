#ifndef C_PORT_FORWARDER_HPP
#define C_PORT_FORWARDER_HPP

#include <thread>
#include "interrupted_sleep.hpp"
#include <atomic>
#include <chrono>
#include <optional>
#include <shared_mutex>
#include <functional>
#include <string>

class c_port_forwarder {
	public:
		using t_broadcast_ip_callback = std::function<void(std::string, unsigned short)>;
		c_port_forwarder(t_broadcast_ip_callback broadcast_ip_callback);
		void start(const unsigned short port);
		virtual ~c_port_forwarder();
		void stop();
		virtual std::optional<std::pair<std::string, unsigned short>> get_my_public_ip() const;
	private:
		t_broadcast_ip_callback m_broadcast_callback;
		unsigned short m_port;
		std::atomic_bool m_stop_flag;
		std::thread m_main_loop_thread;
		c_interrupted_sleep m_sleeper_reannounce;
		c_interrupted_sleep m_sleeper_retry;
		const std::chrono::minutes m_port_mapping_reannounce_period = std::chrono::minutes(20);
		const std::chrono::minutes m_port_mapping_retry_period = std::chrono::minutes(5);
		mutable std::shared_mutex m_my_public_address_mutex;
		std::optional<std::pair<std::string, unsigned short>> m_my_public_address;
		bool forward_port_upnp();
		bool addr_is_reserved(struct in_addr * addr) const noexcept;
		#ifdef NATPMP
		bool forward_port_natpmp();
		#endif
		void main_loop();
};

#endif // C_PORT_FORWARDER_HPP
