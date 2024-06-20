#ifndef MAIN_MODULE_HPP
#define MAIN_MODULE_HPP

#include "mediator.hpp"
#include "blockchain_module.hpp"
#include "p2p_module.hpp"
#include "rpc_module.hpp"
#include <condition_variable>

class c_main_module : public c_mediator {
	friend class c_main_module_builder;
	friend std::unique_ptr<c_main_module> std::make_unique<c_main_module>();
	friend class c_main_module_mock_builder;
	public:
		std::unique_ptr<t_mediator_command_response> notify(const t_mediator_command_request & request) override;
		std::unique_ptr<t_mediator_command_response> notify(const t_mediator_command_request & request) const override;
		void run();
		~c_main_module() override = default;
	private:
		c_main_module() = default;
		std::unique_ptr<c_blockchain_module> m_blockchain_module;
		std::unique_ptr<c_p2p_module> m_p2p_module;
		std::unique_ptr<c_rpc_module> m_rpc_module;
		std::mutex m_stop_cv_mutex;
		std::condition_variable m_stop_cv;
		bool m_stopped = false;
		void stop();
};

#endif // MAIN_MODULE_HPP
