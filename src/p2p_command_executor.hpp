#ifndef C_P2P_COMMAND_EXECUTOR_HPP
#define C_P2P_COMMAND_EXECUTOR_HPP

#include "span.hpp"
#include "peer_reference.hpp"
#include "params.hpp"

enum class e_p2p_command : unsigned char {
	ping = 0,
	ping_response = ping + n_networkparams::response_offset,

	blockchain_height = 1,
	blockchain_height_response = blockchain_height + n_networkparams::response_offset,

	get_block = 2,
	get_block_response = get_block + n_networkparams::response_offset,

	request_mix = 3,
	request_mix_response = request_mix + n_networkparams::response_offset,

	i_want_subscribe_mix = 4,
	i_want_subscribe_mix_response = i_want_subscribe_mix + n_networkparams::response_offset,

	send_transaction = 5,
	send_transaction_response = send_transaction + n_networkparams::response_offset,

	vote_list_add_request = 6,
	vote_list_add_response = vote_list_add_request + n_networkparams::response_offset,

	vote_list_delete_request = 7,
	vote_list_delete_response = vote_list_delete_request + n_networkparams::response_offset,

	vote_list_edit_request = 8, // todo example, on update elections
	vote_list_edit_response = vote_list_edit_request + n_networkparams::response_offset,

	message = 9,
	message_response = message + n_networkparams::response_offset,

	get_block_header = 10,
	get_block_header_response = get_block_header + n_networkparams::response_offset,

	get_block_segment_tx = 11,
	get_block_segment_tx_response = get_block_segment_tx + n_networkparams::response_offset,

	get_block_segment_checksum = 12,
	get_block_segment_checksum_response = get_block_segment_checksum + n_networkparams::response_offset,

	get_block_segment_signature = 13,
	get_block_segment_signature_response = get_block_segment_signature + n_networkparams::response_offset,

	send_block_header = 14,
	send_block_header_response = send_block_header + n_networkparams::response_offset

};

#endif // C_P2P_COMMAND_EXECUTOR_HPP
