#ifndef SERIALIZATION_UTILS_HPP
#define SERIALIZATION_UTILS_HPP

#include "block_record.hpp"
#include "block.hpp"
#include "transaction.hpp"
#include "p2p.pb.h"
#include "types.hpp"

template <class TPROTO_TYPE>
TPROTO_TYPE deserialize_to_proto(const std::string & serialized_data) {
	TPROTO_TYPE proto_type;
	proto_type.ParseFromArray(serialized_data.data(), static_cast<int>(serialized_data.size()));
	return proto_type;
}

proto::header header_to_protobuf(const c_header & header);
c_header header_from_protobuf(const proto::header & header_proto);
proto::block block_to_protobuf(const c_block & block);
c_block block_from_protobuf(const proto::block & block_proto);
proto::transaction transaction_to_protobuf(const c_transaction & tx);
proto::transaction::vout vout_to_protobuf(const c_vout & vout);
proto::transaction::vin vin_to_protobuf(const c_vin & vin);

c_transaction transaction_from_protobuf(const proto::transaction & transaction_proto);
c_vout vout_from_protobuf(const proto::transaction::vout & vout_proto);
c_vin vin_from_protobuf(const proto::transaction::vin & vin_proto);

std::string serialize_to_string(const c_block_record & block_record);
std::string serialize_to_string(const c_file_info_record & file_info_record);
std::string serialize_to_string(const c_transaction_record & transaction_record);
std::string serialize_to_string(const c_header & header);
std::string serialize_to_string(const c_block & block);
std::string serialize_to_string(const c_transaction & transaction);
std::string serialize_to_string(const c_vout & vout);
std::string serialize_to_string(const c_vin & vin);

template <class T>
T deserialize_from_string(const std::string & serialized_data) = delete;

template<> c_block_record deserialize_from_string<c_block_record>(const std::string & serialized_data);
template<> c_file_info_record deserialize_from_string<c_file_info_record>(const std::string & serialized_data);
template<> c_transaction_record deserialize_from_string<c_transaction_record>(const std::string & serialized_data);
template<> c_header deserialize_from_string<c_header>(const std::string & serialized_data);
template<> c_block deserialize_from_string<c_block>(const std::string & serialized_data);
template<> c_transaction deserialize_from_string<c_transaction>(const std::string & serialized_data);
template<> c_vout deserialize_from_string<c_vout>(const std::string & serialized_data);
template<> c_vin deserialize_from_string<c_vin>(const std::string & serialized_data);

#endif // SERIALIZATION_UTILS_HPP
