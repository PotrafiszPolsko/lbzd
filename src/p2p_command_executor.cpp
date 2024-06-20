#include "p2p_command_executor.hpp"

c_p2p_command_executor::c_p2p_command_executor(std::function<void (const c_peer_reference &, const std::string &)> && write_function)
:
	  m_write_functor(std::move(write_function))
{
}

void c_p2p_command_executor::add_command_handler(e_p2p_command command, const t_executor_function & functor) {
    std::cerr<<"add handler for command command " << static_cast<int>(command)<<std::endl;
    m_commands.emplace(command, functor);
}

void c_p2p_command_executor::read_command(const c_peer_reference & peer, stdpfp::span<const std::byte> data) {
	if (data.size() < 1) return;
	const e_p2p_command command = static_cast<e_p2p_command>(data[0]);
    std::cerr<<"read command from peer " << peer.to_string()<<std::endl;
    std::cerr<<"command size " << data.size()<<std::endl;
    std::cerr<<"command: " << static_cast<int>(command)<<std::endl;
    try {
		std::string args(reinterpret_cast<const char *>(data.data()), data.size());
		args.erase(args.begin()); // remove 1st byte (command number)
        std::cerr<<"args " << args<<std::endl;
		if (static_cast<unsigned char>(command) >= response_offset) {
            std::cerr<<"response handler"<<std::endl;
			m_commands.at(command)(args, peer);
			return;
		}
		std::string response = m_commands.at(command)(args, peer);
		if (response.empty()) return;
        std::cerr<<"write to " << peer.to_string()<<std::endl;
		m_write_functor(peer, response);
    } catch (const std::exception & e) {
        std::cerr<<e.what()<<std::endl;
    }
}

void c_p2p_command_executor::send_command(const c_peer_reference & peer, e_p2p_command command, stdpfp::span<const std::byte> data) {
    std::cerr<<"send command to peer " << peer.to_string()<<std::endl;
    std::string full_command;
	full_command += static_cast<char>(command);
	if ((data.data() != nullptr) && (data.size() != 0)) {
		full_command += std::string(reinterpret_cast<const char *>(data.data()), data.size());
	}

	try {
		m_write_functor(peer, full_command);
    } catch (const std::exception & e) {
        std::cerr<<"Exception on send_command : "<<e.what()<<std::endl;
    }
}

void c_p2p_command_executor::set_write_functor(const std::function<void (const c_peer_reference &, const std::string &)> &write_functor) {
	m_write_functor = write_functor;
}
