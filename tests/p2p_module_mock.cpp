#include "p2p_module_mock.hpp"

c_mediator_stub c_p2p_module_mock::m_mediator_stub;

c_p2p_module_mock::c_p2p_module_mock()
    :
	c_p2p_module(m_mediator_stub)
{	
}
