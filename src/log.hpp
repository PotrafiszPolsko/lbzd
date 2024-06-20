#ifndef C_LOG_HPP
#define C_LOG_HPP
#include "blockchain.hpp"
#include "types.hpp"
#include <sstream>
#include <iomanip>

class c_log {
	public:
		c_log(const c_blockchain &blockchain);
		void write_in_log_file() const;
	private:
		const c_blockchain &m_blockchain;
	};

template<typename T>
std::string convert_array_or_vector_byte_to_hex_string(const T &container) {
	std::ostringstream hex;
	for(size_t i=0; i<container.size(); i++) {
		hex<<"0x";
		hex<<std::hex << std::setfill('0');
		hex<<std::setw(2)<<static_cast<int>(container.at(i));
		if(i!=container.size()-1) hex<<",";
	}
	return hex.str();
}

#endif // C_LOG_HPP
