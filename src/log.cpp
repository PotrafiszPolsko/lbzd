#include "log.hpp"
#include "logger.hpp"
#include <fstream>

c_log::c_log(const c_blockchain &blockchain)
:
    m_blockchain(blockchain)
{
}

void c_log::write_in_log_file() const {
    std::ofstream log;
	log.open("BC.log", std::ios::out);
	if( log.good() == false ) {
		LOG(error) << "file BC.log not found";
		throw std::runtime_error("Log file creation error");
	}
	for(const auto &block:m_blockchain.get_blocks()){
		log<<"version of blockchain: "<<static_cast<unsigned int>(block.m_header.m_version)<<std::endl;
		log<<"parent hash: "<<convert_array_or_vector_byte_to_hex_string(block.m_header.m_parent_hash)<<std::endl;
		log<<"actual hash: "<<convert_array_or_vector_byte_to_hex_string(block.m_header.m_actual_hash)<<std::endl;
		log<<"time minning of block: "<<static_cast<unsigned int>(block.m_header.m_block_time)<<std::endl;
		log<<"all tx hash: "<<convert_array_or_vector_byte_to_hex_string(block.m_header.m_all_tx_hash)<<std::endl;
		for(const auto &signature:block.m_header.m_all_signatures) {
			log<<"signature: "<<convert_array_or_vector_byte_to_hex_string(signature)<<std::endl;
		}
		for(const auto &tx:block.m_transaction) {
			log<<"tx type: "<<static_cast<unsigned int>(tx.m_type)<<std::endl;
			for(const auto &vin:tx.m_vin) {
				log<<"vin-txid: "<<convert_array_or_vector_byte_to_hex_string(vin.m_txid)<<std::endl;
				log<<"vin-signature: "<<convert_array_or_vector_byte_to_hex_string(vin.m_sign)<<std::endl;
				log<<"vin-public key: "<<convert_array_or_vector_byte_to_hex_string(vin.m_pk)<<std::endl;
			}
			for(const auto &vout:tx.m_vout) {
				log<<"vout-public key hash: "<<convert_array_or_vector_byte_to_hex_string(vout.m_pkh)<<std::endl;
				log<<"vout-amount: "<<static_cast<unsigned int>(vout.m_amount)<<std::endl;
			}
			log<<"tx-txid: "<<convert_array_or_vector_byte_to_hex_string(tx.m_txid)<<std::endl;
			log<<"tx-all meta data: "<<convert_array_or_vector_byte_to_hex_string(tx.m_allmetadata)<<std::endl;
		}
	}
	log.close();
}
