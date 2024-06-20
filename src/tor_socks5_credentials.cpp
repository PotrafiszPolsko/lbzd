#include "tor_socks5_credentials.hpp"

bool operator<(const tor_socks5_credentials &lhs, const tor_socks5_credentials &rhs) {
	if (lhs.m_username_soks5 < rhs.m_username_soks5) return true;
	if (lhs.m_password_soks5 < rhs.m_password_soks5) return true;
	return false;
}

bool operator==(const tor_socks5_credentials &lhs, const tor_socks5_credentials &rhs) {
	if (lhs.m_username_soks5 != rhs.m_username_soks5) return false;
	if (lhs.m_password_soks5 != rhs.m_password_soks5) return false;
	return true;
}

bool operator!=(const tor_socks5_credentials &lhs, const tor_socks5_credentials &rhs) {
	return !(lhs == rhs);
}
