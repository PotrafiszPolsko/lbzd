#include "serialization_utils.hpp"
#include "blockchain.pb.h"
#include "utils.hpp"

std::string serialize_to_string(const c_block_record & block_record) {
	proto::block_record block_record_proto;
	const auto header_proto = header_to_protobuf(block_record.m_header);
	block_record_proto.mutable_m_header()->CopyFrom(header_proto);
	block_record_proto.set_m_height(block_record.m_height);
	block_record_proto.set_m_number_of_transactions(block_record.m_number_of_transactions);
	block_record_proto.set_m_file_contains_block(block_record.m_file_contains_block);
	block_record_proto.set_m_position_in_file(block_record.m_position_in_file);
	block_record_proto.set_m_size_of_binary_data(block_record.m_size_of_binary_data);
	return block_record_proto.SerializeAsString();
}

std::string serialize_to_string(const c_file_info_record & file_info_record) {
	proto::file_info_record file_info_record_proto;
	file_info_record_proto.set_m_number_of_blocks(file_info_record.m_number_of_blocks);
	file_info_record_proto.set_m_filesize(file_info_record.m_filesize);
	file_info_record_proto.set_m_height_lowest(file_info_record.m_height_lowest);
	file_info_record_proto.set_m_height_highest(file_info_record.m_height_highest);
	return file_info_record_proto.SerializeAsString();
}

std::string serialize_to_string(const c_transaction_record & transaction_record) {
	proto::transaction_record transaction_record_proto;
	transaction_record_proto.set_m_file_contains_block(transaction_record.m_file_contains_block);
	transaction_record_proto.set_m_offset_of_block(transaction_record.m_offset_of_block);
	transaction_record_proto.set_m_offset_of_transaction(transaction_record.m_offset_of_transaction);
	transaction_record_proto.set_m_blockid(container_to_string(transaction_record.m_block_id));
	return transaction_record_proto.SerializeAsString();
}

std::string serialize_to_string(const c_header & header) {
	const auto header_proto = header_to_protobuf(header);
	return header_proto.SerializeAsString();
}

std::string serialize_to_string(const c_block & block) {
	const auto block_proto = block_to_protobuf(block);
	return block_proto.SerializeAsString();
}
std::string serialize_to_string(const c_vout & vout) {
	const auto vout_proto = vout_to_protobuf(vout);
	return vout_proto.SerializeAsString();
}

std::string serialize_to_string(const c_vin & vin) {
	const auto vin_proto = vin_to_protobuf(vin);
	return vin_proto.SerializeAsString();
}

proto::transaction::vout vout_to_protobuf(const c_vout & vout) {
	proto::transaction::vout vout_proto;
	vout_proto.set_m_pkh(container_to_string(vout.m_pkh));
	vout_proto.set_m_amount(vout.m_amount);
	return vout_proto;
}

proto::transaction::vin vin_to_protobuf(const c_vin & vin) {
	proto::transaction::vin vin_proto;
	vin_proto.set_m_txid(container_to_string(vin.m_txid));
	vin_proto.set_m_sign(container_to_string(vin.m_sign));
	vin_proto.set_m_pk(container_to_string(vin.m_pk));
	return vin_proto;
}

proto::transaction transaction_to_protobuf(const c_transaction & tx){
	proto::transaction transaction_proto;
	transaction_proto.set_m_type(proto::transaction_transactiontype(tx.m_type));
	for (const auto & vin : tx.m_vin) {
		auto * const vin_proto = transaction_proto.add_m_vin();
		vin_proto->CopyFrom(vin_to_protobuf(vin));
	}
	for (const auto & vout : tx.m_vout) {
		auto * const vout_proto = transaction_proto.add_m_vout();
		vout_proto->CopyFrom(vout_to_protobuf(vout));
	}
	transaction_proto.set_m_txid(container_to_string(tx.m_txid));
	transaction_proto.set_m_allmetadata(container_to_string(tx.m_allmetadata));
	return transaction_proto;
}

proto::block block_to_protobuf(const c_block & block) {
	auto header_proto = header_to_protobuf(block.m_header);
	proto::block block_proto;
	block_proto.mutable_m_header()->CopyFrom(header_proto);
	for (const auto & tx : block.m_transaction) {
		auto * const new_tx_proto = block_proto.add_m_transaction();
		auto transaction_proto = transaction_to_protobuf(tx);
		new_tx_proto->CopyFrom(transaction_proto);
	}
	return block_proto;
}

c_block block_from_protobuf(const proto::block & block_proto) {
	c_block block;
	const auto & header_proto = block_proto.m_header();
	block.m_header = header_from_protobuf(header_proto);
	for (int i = 0; i < block_proto.m_transaction_size(); i++) {
		const auto & transaction_proto = block_proto.m_transaction(i);
		auto transaction = transaction_from_protobuf(transaction_proto);
		block.m_transaction.push_back(std::move(transaction));
	}
	return block;
}

proto::header header_to_protobuf(const c_header & header) {
	proto::header header_proto;
	header_proto.set_m_version(header.m_version);
	header_proto.set_m_parent_hash(container_to_string(header.m_parent_hash));
	header_proto.set_m_actual_hash(container_to_string(header.m_actual_hash));
	header_proto.set_m_block_time(header.m_block_time);
	header_proto.set_m_all_tx_hash(container_to_string(header.m_all_tx_hash));
	for (const auto & signature : header.m_all_signatures) {
		auto signature_as_string = container_to_string(signature);
		header_proto.add_m_all_signatures(std::move(signature_as_string));
	}
	return header_proto;
}

template<> c_block_record deserialize_from_string<c_block_record>(const std::string & serialized_data) {
	const auto block_record_proto = deserialize_to_proto<proto::block_record>(serialized_data);
	c_block_record block_record;
	const auto & header_proto = block_record_proto.m_header();
	block_record.m_header = header_from_protobuf(header_proto);
	block_record.m_height = block_record_proto.m_height();
	block_record.m_number_of_transactions = block_record_proto.m_number_of_transactions();
	block_record.m_file_contains_block = block_record_proto.m_file_contains_block();
	block_record.m_position_in_file = block_record_proto.m_position_in_file();
	block_record.m_size_of_binary_data = block_record_proto.m_size_of_binary_data();
	return block_record;
}

template<> c_file_info_record deserialize_from_string<c_file_info_record>(const std::string & serialized_data) {
	const auto file_info_record_proto = deserialize_to_proto<proto::file_info_record>(serialized_data);
	c_file_info_record file_info_record;
	file_info_record.m_number_of_blocks = file_info_record_proto.m_number_of_blocks();
	file_info_record.m_filesize = file_info_record_proto.m_filesize();
	file_info_record.m_height_lowest = file_info_record_proto.m_height_lowest();
	file_info_record.m_height_highest = file_info_record_proto.m_height_highest();
	return file_info_record;
}

template<> c_transaction_record deserialize_from_string<c_transaction_record>(const std::string & serialized_data) {
	const auto transaction_record_proto = deserialize_to_proto<proto::transaction_record>(serialized_data);
	c_transaction_record transaction_record;
	transaction_record.m_file_contains_block = transaction_record_proto.m_file_contains_block();
	transaction_record.m_offset_of_block = transaction_record_proto.m_offset_of_block();
	transaction_record.m_offset_of_transaction = transaction_record_proto.m_offset_of_transaction();
	transaction_record.m_block_id = transform_string_to_array<hash_size>(transaction_record_proto.m_blockid());
	return transaction_record;
}

template<> c_header deserialize_from_string<c_header>(const std::string & serialized_data) {
	const auto header_proto = deserialize_to_proto<proto::header>(serialized_data);
	return header_from_protobuf(header_proto);
}

template<> c_block deserialize_from_string<c_block>(const std::string & serialized_data) {
	const auto block_proto = deserialize_to_proto<proto::block>(serialized_data);
	return block_from_protobuf(block_proto);
}

template<> c_transaction deserialize_from_string<c_transaction>(const std::string & serialized_data) {
	const auto transaction_proto = deserialize_to_proto<proto::transaction>(serialized_data);
	return transaction_from_protobuf(transaction_proto);
}

template<> c_vout deserialize_from_string<c_vout>(const std::string & serialized_data) {
	const auto vout_proto = deserialize_to_proto<proto::transaction::vout>(serialized_data);
	return vout_from_protobuf(vout_proto);
}

template<> c_vin deserialize_from_string<c_vin>(const std::string & serialized_data) {
	const auto vin_proto = deserialize_to_proto<proto::transaction::vin>(serialized_data);
	return vin_from_protobuf(vin_proto);
}


std::string serialize_to_string(const c_transaction & transaction) {
	const auto tx_proto = transaction_to_protobuf(transaction);
	return tx_proto.SerializeAsString();
}

c_header header_from_protobuf(const proto::header & header_proto) {
	c_header header;
	header.m_version = static_cast<uint8_t>(header_proto.m_version());
	header.m_parent_hash = transform_string_to_array<hash_size>(header_proto.m_parent_hash());
	header.m_actual_hash = transform_string_to_array<hash_size>(header_proto.m_actual_hash());
	header.m_block_time = header_proto.m_block_time();
	header.m_all_tx_hash = transform_string_to_array<hash_size>(header_proto.m_all_tx_hash());
	for (int i = 0; i < header_proto.m_all_signatures_size(); i++) {
		const std::string signature_as_string = header_proto.m_all_signatures(i);
		constexpr size_t signature_size = std::tuple_size<t_signature_type>::value;
		t_signature_type signature = transform_string_to_array<signature_size>(signature_as_string);
		header.m_all_signatures.emplace_back(signature);
	}
	return header;
}

c_transaction transaction_from_protobuf(const proto::transaction & transaction_proto) {
	c_transaction transaction;
	transaction.m_type = static_cast<t_transactiontype>(transaction_proto.m_type());
	for (int i = 0; i < transaction_proto.m_vin_size(); i++) {
		const auto & vin_proto = transaction_proto.m_vin(i);
		auto vin = vin_from_protobuf(vin_proto);
		transaction.m_vin.emplace_back(std::move(vin));
	}
	for (int i = 0; i < transaction_proto.m_vout_size(); i++) {
		const auto & vout_proto = transaction_proto.m_vout(i);
		auto vout = vout_from_protobuf(vout_proto);
		transaction.m_vout.emplace_back(std::move(vout));
	}
	transaction.m_txid = transform_string_to_array<hash_size>(transaction_proto.m_txid());
	const auto & all_metadata_as_string = transaction_proto.m_allmetadata();
	std::copy(all_metadata_as_string.cbegin(), all_metadata_as_string.cend(), std::back_inserter(transaction.m_allmetadata));
	return transaction;
}

c_vout vout_from_protobuf(const proto::transaction::vout & vout_proto) {
	c_vout vout;
	vout.m_pkh = transform_string_to_array<hash_size>(vout_proto.m_pkh());
	vout.m_amount = vout_proto.m_amount();
	return vout;
}

c_vin vin_from_protobuf(const proto::transaction::vin & vin_proto) {
	constexpr size_t signature_size = std::tuple_size<t_signature_type>::value;
	constexpr size_t pk_size = std::tuple_size<t_public_key_type>::value;
	c_vin vin;
	vin.m_txid = transform_string_to_array<hash_size>(vin_proto.m_txid());
	if ((vin_proto.has_m_sign()) && (vin_proto.m_sign().size() > 0))
		vin.m_sign = transform_string_to_array<signature_size>(vin_proto.m_sign());
	else 
		vin.m_sign.fill(0x00);
	vin.m_pk = transform_string_to_array<pk_size>(vin_proto.m_pk());
	return vin;
}


