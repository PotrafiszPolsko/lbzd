#ifndef BLOCKCHAIN_PARAMS_HPP
#define BLOCKCHAIN_PARAMS_HPP

#include "types.hpp"

namespace n_blockchainparams {
	constexpr std::array<t_public_key_type,3> admins_sys_pub_keys = { 
                                                   {{0x6e, 0x07, 0x38, 0x89,
                                                     0x56, 0xfd, 0xed, 0x04,
                                                     0x5f, 0xa8, 0x77, 0xea,
                                                     0x0e, 0x2d, 0x1a, 0xd5,
                                                     0xbc, 0x46, 0x5a, 0xe9,
                                                     0x05, 0x22, 0x19, 0xf8,
                                                     0x11, 0x4a, 0x5e, 0xe3,
                                                     0x1e, 0x02, 0x5e, 0xef},

                                                    {0x03, 0x11, 0xd2, 0x96,
                                                     0x3d, 0x7e, 0x03, 0xe9,
                                                     0x35, 0x15, 0x4f, 0x07,
                                                     0xc2, 0x5a, 0x65, 0xd7,
                                                     0xed, 0x13, 0xb8, 0xc8,
                                                     0x40, 0x28, 0xb1, 0xf2,
                                                     0x19, 0xeb, 0x75, 0xef,
                                                     0x6c, 0x01, 0x71, 0xd5},

                                                    {0x1e, 0xe1, 0x40, 0x39,
                                                     0x26, 0x82, 0xa4, 0x30,
                                                     0x81, 0xbf, 0x99, 0x2e,
                                                     0xdc, 0x8c, 0xaf, 0xc9,
                                                     0x3c, 0xa7, 0x0c, 0xf6,
                                                     0x24, 0x91, 0x6d, 0x6c,
                                                     0xa1, 0x10, 0xb1, 0x44,
                                                     0xf8, 0xf9, 0x6a, 0xdc}}
	};

	bool is_pk_adminsys(const t_public_key_type &pk);

	constexpr size_t minimal_valid_signatures_in_block = 1;
	constexpr size_t percent_of_miners_needed_to_sign_block = 50;
#if defined (IVOTING_TESTS) || defined (COVERAGE_TESTS)
	constexpr size_t blocks_diff_time_in_sec = 10;
	constexpr size_t block_diff_time_deviation_in_sec = 1;
#else
	constexpr size_t blocks_diff_time_in_sec = 5 * 60;
	constexpr size_t block_diff_time_deviation_in_sec = 30;
#endif
	constexpr size_t number_of_rows_mixes_to_vote = 10;
	constexpr size_t number_of_voters_in_mix = 5; // 5 is max number
	static_assert(number_of_voters_in_mix>=3 && number_of_voters_in_mix<=5);
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
	constexpr unsigned short port_p2p_tcp = 22083;	///< (default) port for peer2peer (tcp) connections
	constexpr unsigned short port_seed_tcp = 22085;	///< (default) port for the seed-servers
	constexpr unsigned short port_p2p_tor = 22086;	///< (default) port for peer2peer (tor/onion) connections
	constexpr unsigned short default_port_tor_socks5 = 9050;
	constexpr unsigned short default_port_tor_control = 9051;
} // namespace

namespace n_seedparams {
	const size_t seed_number_of_bytes = seed_bytes;
	constexpr size_t seed_bits_of_one_word = 11; ///< each word will be converted to 11-bit number
	constexpr size_t seed_number_of_words = 12; ///< words of the seed (main words)
	constexpr size_t seed_number_of_entropy_bytes = 16; ///< entropy = array of bytes of words numbers + checksum
	constexpr size_t seed_number_of_csum_bits = 4; ///< for each 32 bit is 1 bit (example: 11 bits of one word, 12 number of words, 32 number of bits ->
														/// -> 11*12/32=4.125 => 4 bit, it means 1 bit for each of the 4 groups of 32 bits (32+1=33) => 11*12/32=4)
} //namespace

namespace n_rpcparams {
	constexpr unsigned int port_rpc_tcp = 22084;
	constexpr std::string_view address_rpc_tcp = "127.0.0.1";
	constexpr unsigned short number_of_blocks_per_page = 10;
	constexpr unsigned short number_of_txs_per_page = 10;
	constexpr unsigned short number_of_txs_from_block_per_page = 5;
	constexpr unsigned short number_of_votings_per_page = 10;
	constexpr unsigned short number_of_block_signatures_per_page = 5;
} //namespace

#endif // BLOCKCHAIN_PARAMS_HPP
