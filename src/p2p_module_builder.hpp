#ifndef P2P_MODULE_BUILDER_HPP
#define P2P_MODULE_BUILDER_HPP

#include "component_builder.hpp"
#include "p2p_module.hpp"

class c_p2p_module_builder : public c_component_builder {
	public:
		void set_program_options(const boost::program_options::variables_map & vm) override;
		std::unique_ptr<c_p2p_module> get_result(c_mediator & mediator) const;
	private:
		boost::program_options::variables_map m_variable_map;
		std::unique_ptr<c_p2p_session_manager_tcp> build_tcp_session_manager(c_p2p_module & p2p_module) const;
		std::unique_ptr<c_p2p_session_manager_tor> build_tor_session_manager(c_p2p_module & p2p_module) const;
		std::unique_ptr<c_peer_finder> build_peer_finder() const;
		void connect_to_peers(c_p2p_session_manager_tcp & session_manager_tcp,
							  c_p2p_session_manager_tor &session_manager_tor) const;
		void ask_for_peers(c_p2p_module & p2p_module) const;
		void ask_for_peers(c_p2p_module & p2p_module, const std::vector<std::unique_ptr<c_peer_reference>> & peer_list) const;
};

#endif // P2P_MODULE_BUILDER_HPP
