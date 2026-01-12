#ifndef BLOCKCHAIN_PARAMS_HPP
#define BLOCKCHAIN_PARAMS_HPP

#include "types.hpp"

namespace n_seedparams {
	const size_t seed_number_of_bytes = seed_bytes;
	constexpr size_t seed_bits_of_one_word = 11; ///< each word will be converted to 11-bit number
	constexpr size_t seed_number_of_words = 12; ///< words of the seed (main words)
	constexpr size_t seed_number_of_entropy_bytes = 16; ///< entropy = array of bytes of words numbers + checksum
	constexpr size_t seed_number_of_csum_bits = 4; ///< for each 32 bit is 1 bit (example: 11 bits of one word, 12 number of words, 32 number of bits ->
														/// -> 11*12/32=4.125 => 4 bit, it means 1 bit for each of the 4 groups of 32 bits (32+1=33) => 11*12/32=4)
} //namespace

namespace n_blockchainparams {

	bool is_pk_adminsys(const t_public_key_type &pk);

	constexpr size_t minimal_valid_signatures_in_block = 1;
	constexpr size_t percent_of_miners_needed_to_sign_block = 50;
#if defined (IVOTING_TESTS) || defined (COVERAGE_TESTS)
	constexpr std::array<t_public_key_type,1> admins_sys_pub_keys = {
                                                   {0x3e, 0xf9, 0x02, 0x25,
                                                     0xad, 0x56, 0x0d, 0xa8,
                                                     0x19, 0xfc, 0x23, 0xc5,
                                                     0x08, 0x89, 0xd1, 0x43,
                                                     0xc2, 0xae, 0x3d, 0xee,
                                                     0xa9, 0x2e, 0x47, 0xd2,
                                                     0xd4, 0x1c, 0xf7, 0x1c,
	                                                 0x0d, 0x40, 0x05, 0x8c}
	};
	constexpr std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> entropy_seed = {
                                                    {0xc7, 0xa4, 0x7f, 0xe8,
                                                     0x6d, 0xf2, 0xe2, 0xd8,
                                                     0xd4, 0x56, 0xb2, 0x80,
	                                                 0x12, 0x46, 0x22, 0x60}
	};
	constexpr size_t blocks_diff_time_in_sec = 3;
	constexpr size_t block_diff_time_deviation_in_sec = 1;
#else
	constexpr std::array<t_public_key_type,3> admins_sys_pub_keys = { 
                                                   {{0xd7, 0x08, 0x7e, 0x3e,
                                                     0x89, 0x1e, 0xbf, 0x7c,
                                                     0x54, 0xe2, 0x16, 0xf4,
                                                     0xa6, 0x69, 0x28, 0x53,
                                                     0xab, 0x01, 0x98, 0x91,
                                                     0x20, 0x46, 0xfe, 0x6e,
                                                     0x48, 0x11, 0xec, 0x85,
                                                     0xa5, 0xe1, 0x1d, 0xf7},

                                                    {0x63, 0xe3, 0x28, 0x05,
                                                     0xee, 0xbc, 0x3a, 0x89,
                                                     0xf2, 0x58, 0x17, 0x84,
                                                     0x37, 0x64, 0x75, 0xe1,
                                                     0xac, 0x61, 0x76, 0xfc,
                                                     0x38, 0x73, 0x13, 0x4b,
                                                     0x16, 0x14, 0x54, 0xb7,
                                                     0x20, 0x42, 0x22, 0x79},

                                                    {0xc7, 0x0b, 0x02, 0xb6,
                                                     0x06, 0x5c, 0x2b, 0x8c,
                                                     0x6c, 0x09, 0x78, 0x16,
                                                     0x76, 0xc1, 0x4b, 0x58,
                                                     0x84, 0x8f, 0x14, 0x24,
                                                     0xce, 0xa5, 0xc2, 0xcd,
                                                     0xe4, 0x5a, 0xb9, 0x93,
                                                     0x98, 0x72, 0xef, 0xd3}}
	};
	constexpr size_t blocks_diff_time_in_sec = 5 * 60;
	constexpr size_t block_diff_time_deviation_in_sec = 30;
#endif
	constexpr size_t max_block_size = 1 * 1024 * 1024; ///< max block size in bytes
	namespace genesis_block_params {
		constexpr uint8_t m_version = 0;
		constexpr t_hash_type m_parent_hash = {0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00};
		constexpr t_hash_type m_all_tx_hash = {0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00,
											   0x00, 0x00, 0x00, 0x00};
	}
} // namespace

namespace n_networkparams {
	constexpr size_t response_offset = 100;
	constexpr unsigned short sleep_to_connect_node = 1;
	constexpr unsigned short port_p2p_tcp = 33333;	///< (default) port for peer2peer (tcp) connections
} // namespace

namespace n_rpcparams {
	constexpr unsigned int port_rpc_tcp = 33334;
	constexpr std::string_view address_rpc_tcp = "127.0.0.1";
	constexpr unsigned short number_of_blocks_per_page = 10;
	constexpr unsigned short number_of_txs_per_page = 10;
	constexpr unsigned short number_of_txs_from_block_per_page = 5;
	constexpr unsigned short number_of_votings_per_page = 10;
	constexpr unsigned short number_of_block_signatures_per_page = 5;
} //namespace

#endif // BLOCKCHAIN_PARAMS_HPP
