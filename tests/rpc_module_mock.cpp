#include "rpc_module_mock.hpp"

c_mediator_stub c_rpc_module_mock::m_mediator_stub;

c_rpc_module_mock::c_rpc_module_mock(std::shared_ptr<c_rpc_exec> exec) 
    :
      c_rpc_module(std::make_unique<c_rpc_server_mock>(exec), m_mediator_stub)
{
}
