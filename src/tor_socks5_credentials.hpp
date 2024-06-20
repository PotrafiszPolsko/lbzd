#include <string>

struct tor_socks5_credentials {
	std::string m_username_soks5; // It's random and from this value depends tor circuit
	std::string m_password_soks5; // It's random and from this value depends tor circuit
	friend bool operator<(const tor_socks5_credentials & lhs, const tor_socks5_credentials & rhs);
	friend bool operator==(const tor_socks5_credentials & lhs,const tor_socks5_credentials & rhs);
	friend bool operator!=(const tor_socks5_credentials & lhs,const tor_socks5_credentials & rhs);
};

bool operator<(const tor_socks5_credentials & lhs, const tor_socks5_credentials & rhs);
bool operator==(const tor_socks5_credentials & lhs,const tor_socks5_credentials & rhs);
bool operator!=(const tor_socks5_credentials & lhs,const tor_socks5_credentials & rhs);

