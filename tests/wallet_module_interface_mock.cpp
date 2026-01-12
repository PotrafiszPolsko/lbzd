#include "wallet_module_interface_mock.hpp"

c_mediator_stub c_wallet_module_mock::m_mediator_stub;

c_wallet_module_mock::c_wallet_module_mock()
    :
	c_wallet_module_interface(m_mediator_stub)
{	
}
