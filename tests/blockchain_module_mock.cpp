#include "blockchain_module_mock.hpp"

c_mediator_stub c_blockchain_module_mock::m_mediator_stub;

c_blockchain_module_mock::c_blockchain_module_mock()
    :
	c_blockchain_module(m_mediator_stub)
{	
}
