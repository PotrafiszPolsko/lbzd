#include "blockchain.hpp"
#include "logger.hpp"
#include "utils.hpp"
#include "serialization_utils.hpp"
#include "merkle_tree.hpp"
#include "params.hpp"
#include <algorithm>
#include <stdexcept>
#include <cmath>

void c_blockchain::create_dir_tree() {
	if(std::filesystem::create_directories(m_blocks_dir_path/"index")) {
		LOG(info) << "Created datadir tree for blockchain: " << m_blocks_dir_path/"index";
	}
}

void c_blockchain::open_blocks_db() const{
	leveldb::Options options;
	options.create_if_missing = true;
    leveldb::DB * db {nullptr};
    const auto blocks_path = m_blocks_dir_path/"index";
	LOG(info) << "Block path: " << blocks_path.string();
    const auto status = leveldb::DB::Open(options, blocks_path.string(), &db);
	m_blocks_database.reset(db);
	if (!status.ok()) throw std::runtime_error("Open blocks db error " + status.ToString());
}

size_t c_blockchain::get_last_blockfile_number() const {
	std::string number;
	auto status = m_blocks_database->Get(leveldb::ReadOptions(), "l", &number);
	if (status.ok()) return std::stoul(number);
	else if (status.IsNotFound()) {
		number = "0";
		status = m_blocks_database->Put(leveldb::WriteOptions(), "l", number);
		return 0;
	}
	else throw std::runtime_error("Write last block number to db error: " + status.ToString());
}

void c_blockchain::increment_last_blockfile_number() const {
	const auto new_blockfile_number = get_last_blockfile_number() + 1;
	const auto number_as_string = std::to_string(new_blockfile_number);
	const auto status = m_blocks_database->Put(leveldb::WriteOptions(), "l", number_as_string);
	if (!status.ok()) throw std::runtime_error("Write last block number to db error: " + status.ToString());
}

c_blockchain::c_blockchain(const std::filesystem::path & datadir_path)
	: 
	  m_datadir_path(datadir_path),
	  m_blocks_dir_path(datadir_path / "blocks")
{
	create_dir_tree();
	open_blocks_db();
}

proto::block c_blockchain::read_block_from_ifstream_proto(std::ifstream & block_file) const {
	std::array<unsigned char, 4> size_of_header_as_array;
	block_file.read(reinterpret_cast<char *>(size_of_header_as_array.data()), size_of_header_as_array.size());
	const uint32_t size_of_header = get_integer<uint32_t>(size_of_header_as_array);
	std::string header_as_string(size_of_header, '\0');
	block_file.read(header_as_string.data(), header_as_string.size());
	auto header_proto = deserialize_to_proto<proto::header>(header_as_string);
	proto::block block_proto;
	block_proto.mutable_m_header()->Swap(&header_proto);
	// transactions
	std::array<unsigned char, 4> number_of_tx_as_array;
	block_file.read(reinterpret_cast<char *>(number_of_tx_as_array.data()), number_of_tx_as_array.size());
	const uint32_t number_of_tx = get_integer<uint32_t>(number_of_tx_as_array);
	for (uint32_t i = 0; i < number_of_tx; i++) {
		std::array<unsigned char, 4> tx_size_as_array;
		block_file.read(reinterpret_cast<char *>(tx_size_as_array.data()), tx_size_as_array.size());
		const uint32_t tx_size = get_integer<uint32_t>(tx_size_as_array);
		std::string tx_as_string(tx_size, '\0');
		block_file.read(tx_as_string.data(), tx_as_string.size());
		auto tx_proto = deserialize_to_proto<proto::transaction>(tx_as_string);
		auto * const new_tx = block_proto.add_m_transaction();
		new_tx->Swap(&tx_proto);
	}
	return block_proto;
}

c_block c_blockchain::get_last_block() const {
	const auto current_height = get_current_height();
	return get_block_at_height(current_height);
}

std::filesystem::path c_blockchain::get_block_filename(size_t file_number) const {
	std::string last_block_filename = "blk" + std::to_string(file_number) + ".dat";
	return last_block_filename;
}

std::filesystem::path c_blockchain::get_block_filename_for_save(size_t file_number, size_t block_as_binary_string_size) const {
	auto last_block_filename = get_block_filename(file_number);
	if (std::filesystem::exists(last_block_filename)) {
		const auto filesize = std::filesystem::file_size(last_block_filename);
		if ((filesize + block_as_binary_string_size) > s_max_size_of_block_file) {
			std::string block_filename = "blk" + std::to_string(file_number + 1) + ".dat";
			increment_last_blockfile_number();
			return block_filename;
		}
	}
	return last_block_filename;
}

size_t c_blockchain::get_current_height() const {
	const std::string db_key = "h";
	std::string height_as_string;
	const auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &height_as_string);
	if (status.IsNotFound()) return -1; // genesis block
	if (!status.ok()) throw std::runtime_error("Read current height from db error: " + status.ToString());
	return std::stoul(height_as_string);
}

proto::header c_blockchain::get_header_proto(const t_hash_type & block_id) const {
	const auto block_record_proto = get_block_record_proto(block_id);
	return block_record_proto.m_header();
}

bool c_blockchain::block_exists(const t_hash_type & block_id) const {
	try {
		get_block_record_as_string(block_id);
		return true;
	} catch (const std::exception &) {
		return false;
	}
}

std::vector<t_hash_type> c_blockchain::get_merkle_branch(const t_hash_type &txid) const {
	const auto block = get_block_by_txid(txid);
	c_merkle_tree mt;
	for(const auto &tx:block.m_transaction) mt.add_hash(tx.m_txid);
	return mt.get_branch_merkle_tree(txid);
}

t_hash_type c_blockchain::get_block_id_by_txid(const t_hash_type &txid) const {
	const std::string txid_as_str = container_to_string(txid);
	const std::string db_key = "t" + txid_as_str;
	std::string transaction_record_as_str;
	const auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &transaction_record_as_str);
	if (!status.ok()) throw std::runtime_error("Read transaction record from db error(get_block_by_txid): " + status.ToString());
	const c_transaction_record transaction_record = deserialize_from_string<c_transaction_record>(transaction_record_as_str);
	return transaction_record.m_block_id;
}

size_t c_blockchain::get_number_of_transactions() const {
	size_t number_of_transactions = 0;
	std::unique_ptr<leveldb::Iterator> it(m_blocks_database->NewIterator(leveldb::ReadOptions()));
	c_block_record block_record;
	for (it->Seek(leveldb::Slice("b")); it->Valid(); it->Next()) {
		const auto status = it->status();
		if (!status.ok()) throw std::runtime_error("iterating db error: " + status.ToString());
		const auto db_key = it->key().ToString();
		if (db_key.front() != 'b') break;
		const auto block_record_as_str = it->value().ToString();
		const auto block_record = deserialize_from_string<c_block_record>(block_record_as_str);
		number_of_transactions += block_record.m_number_of_transactions;
	}
	return number_of_transactions;
}

std::vector<c_block_record> c_blockchain::get_last_5_blocks() const {
	const auto current_height = get_current_height();
	const auto all_blocks_record = get_all_sorted_record_blocks(current_height);
	std::vector<c_block_record> specific_number_blocks_record;
	std::copy_n(all_blocks_record.cbegin(), 5, std::back_inserter(specific_number_blocks_record));
	return specific_number_blocks_record;
}

std::vector<c_transaction> c_blockchain::get_last_5_transactions() const {
	std::vector<c_transaction> txs;
	const auto blocks_record = get_sorted_record_blocks_with_txs_only();
	for(const auto &block_record:blocks_record) {
		const auto block_height = block_record.m_height;
		const auto block = get_block_at_height(block_height);
		const auto number_of_transactions = block.m_transaction.size();
		auto block_transactions = block.m_transaction;
		std::sort(block_transactions.begin(), block_transactions.end(),
		[](const c_transaction & tx_1, const c_transaction & tx_2){return tx_1.m_txid < tx_2.m_txid;});
		size_t actual_number_txs;
		if(number_of_transactions<5 - txs.size()) actual_number_txs = number_of_transactions;
		else actual_number_txs = 5 - txs.size();
		std::copy_n(block_transactions.cbegin(), actual_number_txs, std::back_inserter(txs));
		if(txs.size()==5) break;
	}
	return txs;
}

std::vector<c_block_record> c_blockchain::get_sorted_blocks(const size_t amount_of_blocks) const {
	const auto current_height = get_current_height();
	const auto all_blocks_record = get_all_sorted_record_blocks(current_height);
	std::vector<c_block_record> blocks_record;
	std::copy_n(all_blocks_record.cbegin(), amount_of_blocks, std::back_inserter(blocks_record));
	return blocks_record;
}

std::pair<std::vector<c_block_record>, size_t> c_blockchain::get_sorted_blocks_per_page(const size_t offset) const {
	if(offset<1) throw std::invalid_argument("blocks offset must be greater than 0");
	const auto current_height = get_current_height();
	const auto all_blocks_record = get_all_sorted_record_blocks(current_height);
	std::vector<c_block_record> blocks_record_per_page;
	if(current_height<n_rpcparams::number_of_blocks_per_page) {
		std::copy(all_blocks_record.cbegin(), all_blocks_record.cend(), std::back_inserter(blocks_record_per_page));
	} else {
		auto height_begin = static_cast<int64_t>(current_height - offset*n_rpcparams::number_of_blocks_per_page);
		if(height_begin<-static_cast<int>(n_rpcparams::number_of_blocks_per_page)) throw std::runtime_error("offset must be less");
		else if(height_begin<0 && height_begin+n_rpcparams::number_of_blocks_per_page>=1) {
			std::copy_n(all_blocks_record.cend()-(height_begin+n_rpcparams::number_of_blocks_per_page), height_begin+n_rpcparams::number_of_blocks_per_page, std::back_inserter(blocks_record_per_page));
		} else {
			std::copy_n(all_blocks_record.cbegin()+(offset-1)*n_rpcparams::number_of_blocks_per_page, n_rpcparams::number_of_blocks_per_page, std::back_inserter(blocks_record_per_page));
		}
	}
	return std::make_pair(blocks_record_per_page, current_height);
}

std::vector<c_transaction> c_blockchain::get_latest_transactions(const size_t amount_txs) const {
	std::vector<c_transaction> txs;
	const auto blocks_record = get_sorted_record_blocks_with_txs_only();
	for(const auto &block_record:blocks_record) {
		const auto block_height = block_record.m_height;
		auto block = get_block_at_height(block_height);
		const auto number_of_transactions = block.m_transaction.size();
		std::sort(block.m_transaction.begin(), block.m_transaction.end(),
		[](const c_transaction & tx_1, const c_transaction & tx_2){return tx_1.m_txid < tx_2.m_txid;});
		size_t actual_number_txs;
		if(number_of_transactions<amount_txs - txs.size()) actual_number_txs = number_of_transactions;
		else actual_number_txs = amount_txs - txs.size();
		std::copy_n(block.m_transaction.cbegin(), actual_number_txs, std::back_inserter(txs));
		if(txs.size()==amount_txs) break;
	}
	return txs;
}

std::pair<std::vector<c_transaction>, size_t> c_blockchain::get_txs_per_page(const size_t offset) const {
	if(offset<1) throw std::invalid_argument("txs offset must be greater than 0");
	size_t end_tx_number = offset*n_rpcparams::number_of_txs_per_page;
	size_t begin_tx_number = end_tx_number - n_rpcparams::number_of_txs_per_page;
	const auto blocks_record = get_sorted_record_blocks_with_txs_only();
	std::vector<c_transaction> txs;
	size_t number_of_transactions = 0;
	size_t total_number_txs = 0;
	for(const auto &block_rekord:blocks_record) total_number_txs += block_rekord.m_number_of_transactions;
	if(begin_tx_number>total_number_txs) throw std::runtime_error("txs offset is too big");
	if(end_tx_number>total_number_txs) end_tx_number = total_number_txs;
	for(size_t counter=0; counter<blocks_record.size(); counter++) {
		number_of_transactions += blocks_record.at(counter).m_number_of_transactions;
		if(number_of_transactions <= begin_tx_number) continue;
		else {
			const size_t prev_number_of_transactions = number_of_transactions - blocks_record.at(counter).m_number_of_transactions;
			const unsigned int begin_to_copy_txs_form_block = static_cast<unsigned int>(begin_tx_number - prev_number_of_transactions);
			const auto block = get_block_at_height(blocks_record.at(counter).m_height);
			auto block_transactions = block.m_transaction;
			std::sort(block_transactions.begin(), block_transactions.end(),
			[](const c_transaction & tx_1, const c_transaction & tx_2){return tx_1.m_txid < tx_2.m_txid;});
			if(end_tx_number <= number_of_transactions && counter<blocks_record.size()-1) {
				std::copy_n(block_transactions.cbegin()+ begin_to_copy_txs_form_block,
				            n_rpcparams::number_of_txs_per_page - txs.size(),
				            std::back_inserter(txs));
			} else {
				std::copy_n(block_transactions.cbegin() + begin_to_copy_txs_form_block,
				            block_transactions.size() - begin_to_copy_txs_form_block,
				            std::back_inserter(txs));
				begin_tx_number += block_transactions.size() - begin_to_copy_txs_form_block;
			}
		}
		if(txs.size()==n_rpcparams::number_of_txs_per_page) break;
	}
	return std::make_pair(txs, total_number_txs);
}

std::pair<std::vector<c_transaction>, size_t> c_blockchain::get_txs_from_block_per_page(const size_t offset, const t_hash_type &block_id) const {
	if(offset<1) throw std::invalid_argument("txs offset from block must be greater than 0");
	const auto block = get_block_at_hash(block_id);
	if(block.m_transaction.empty()) throw std::runtime_error("There are no txs in the block");
	auto block_transactions = block.m_transaction;
	std::sort(block_transactions.begin(), block_transactions.end(),
	[](const c_transaction & tx_1, const c_transaction & tx_2){return tx_1.m_txid < tx_2.m_txid;});
	std::vector<c_transaction> txs;
	if(block_transactions.size()<n_rpcparams::number_of_txs_from_block_per_page) {
		std::copy(block_transactions.cbegin(), block_transactions.cend(), std::back_inserter(txs));
	} else {
		const unsigned int txs_begin =static_cast<unsigned int>( (offset-1)*n_rpcparams::number_of_txs_from_block_per_page );
		const size_t txs_end = txs_begin + n_rpcparams::number_of_txs_from_block_per_page;
		if(block_transactions.size()<=txs_begin) throw std::runtime_error("txs offset from block is too big");
		if(txs_end<=block_transactions.size()) {
			std::copy_n(block_transactions.cbegin()+txs_begin, n_rpcparams::number_of_txs_from_block_per_page, std::back_inserter(txs));
		} else {
			std::copy_n(block_transactions.cbegin()+txs_begin, block.m_transaction.size()-txs_begin, std::back_inserter(txs));
		}
	}
	return std::make_pair(txs, block_transactions.size());
}

void c_blockchain::save_block_record(c_block_record & block_record) {
	// save 'b' record
	std::string db_key = "b";
	const auto block_hash = block_record.m_header.m_actual_hash;
	db_key += container_to_string(block_hash);
	// serialize record
	std::string block_record_as_string = serialize_to_string(block_record);
	// save to database
	const auto status = m_blocks_database->Put(leveldb::WriteOptions(), db_key, block_record_as_string);
	if (!status.ok()) throw std::runtime_error("Write block record to db error: " + status.ToString());
}

void c_blockchain::save_file_information(size_t file_number, const std::filesystem::path & block_filename) {
	file_number = get_file_number_from_blk_path(block_filename);
	std::string db_key = "f" + std::to_string(file_number);
	std::string record_as_string;
	auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &record_as_string);
	c_file_info_record file_info_record;
	if (status.ok()) { // not new file
		file_info_record = deserialize_from_string<c_file_info_record>(record_as_string);
		file_info_record.m_number_of_blocks++;
		file_info_record.m_filesize = static_cast<unsigned int>(std::filesystem::file_size(block_filename));
		file_info_record.m_height_highest++;
	} else { // new file
		file_info_record.m_number_of_blocks = 1;
		file_info_record.m_filesize = static_cast<unsigned int>(std::filesystem::file_size(block_filename));
		const auto current_height = static_cast<unsigned int>(get_current_height());
		if (current_height == 0) { // add genesis block
			file_info_record.m_height_lowest = 0;
			file_info_record.m_height_highest = 0;
		} else {
			file_info_record.m_height_lowest = current_height;
			file_info_record.m_height_highest = current_height;
		}
	}
	record_as_string = serialize_to_string(file_info_record);
	status = m_blocks_database->Put(leveldb::WriteOptions(), db_key, record_as_string);
	if (!status.ok()) throw std::runtime_error("Write file info record to db error: " + status.ToString());
}

void c_blockchain::write_last_block_file_number(size_t file_number) {
	const std::string last_block_file_number_as_string = std::to_string(file_number);
	auto status = m_blocks_database->Put(leveldb::WriteOptions(), "l", last_block_file_number_as_string);
	if (!status.ok()) throw std::runtime_error("Write last block file number db error: " + status.ToString());
}

void c_blockchain::add_block(const c_block & block) {
	const auto &blockid = block.m_header.m_actual_hash;
	const auto current_height = get_current_height() + 1;
	{
		std::string blockid_str;
		blockid_str.resize(2*blockid.size()+1);
		sodium_bin2hex(blockid_str.data(), blockid_str.size(), blockid.data(), blockid.size());
		LOG(info) << "add new block to blockchain, block id is " << blockid_str;
		LOG(info) << "block current height is " << current_height;
	}
	// serialize block
	c_header header = block.m_header;
	const std::string header_as_string = serialize_to_string(header);
	size_t size_of_transaction_segment = 0;
	constexpr size_t byted_for_size = 4;
	std::vector<std::string> serialized_transactions;
	for (const auto &tx : block.m_transaction) {
		size_of_transaction_segment += byted_for_size; // for number of bytes transaction
		auto serialized_transaction = serialize_to_string(tx);
		size_of_transaction_segment += serialized_transaction.size();
		serialized_transactions.emplace_back(std::move(serialized_transaction));
	}
	const auto file_number = get_last_blockfile_number();
	// get block filename
	const auto block_base_filename = get_block_filename_for_save(file_number, size_of_transaction_segment);
	const auto block_absolute_filename = m_blocks_dir_path / block_base_filename;
	// write block to .dat file
	// format: 4B for header size, header bytes, 4B number of transacrions, n-times (4B tx size + tx bytes)
	std::ofstream block_file(block_absolute_filename, std::ios::binary | std::ios::out | std::ios::app);
	const unsigned int file_position_block_begin = static_cast<unsigned int>(block_file.tellp());
	const auto header_size = get_array_byte<uint32_t>(static_cast<uint32_t>(header_as_string.size()));
	assert(header_size.size() == 4);
	block_file.write(reinterpret_cast<const char *>(header_size.data()), header_size.size()); // size of header
	block_file.write(header_as_string.data(), static_cast<unsigned int>(header_as_string.size())); // header
	const auto number_of_transactions = get_array_byte<uint32_t>(static_cast<uint32_t>(block.m_transaction.size()));
	block_file.write(reinterpret_cast<const char *>(number_of_transactions.data()), number_of_transactions.size());
	auto transactions_vector = block.m_transaction;
	assert(transactions_vector.size() == serialized_transactions.size());
	for (size_t i = 0; i < transactions_vector.size(); i++) {
		const unsigned int transaction_position_in_file = static_cast<unsigned int>(block_file.tellp());
		const auto serialized_transaction = serialized_transactions.at(i);
		const auto size_of_tx = get_array_byte<uint32_t>(static_cast<uint32_t>(serialized_transaction.size()));
		block_file.write(reinterpret_cast<const char *>(size_of_tx.data()), size_of_tx.size());
		block_file.write(serialized_transaction.data(), static_cast<unsigned int>(serialized_transaction.size()));
		c_transaction_record transaction_record;
		transaction_record.m_file_contains_block = block_base_filename.string();
		transaction_record.m_offset_of_block = file_position_block_begin;
		transaction_record.m_offset_of_transaction = static_cast<unsigned int>(transaction_position_in_file) - file_position_block_begin;
		transaction_record.m_block_id = blockid;
		const auto transaction_record_as_str = serialize_to_string(transaction_record);
		const auto txid = transactions_vector.at(i).m_txid;
		std::string txid_as_str = container_to_string(txid);
		const std::string db_key = "t" + txid_as_str;
		const auto status = m_blocks_database->Put(leveldb::WriteOptions(), db_key, transaction_record_as_str);
		if (!status.ok()) throw std::runtime_error("Save txid to db error: " + status.ToString());
	}
	// write block record
	c_block_record block_record;
	block_record.m_header = block.m_header;

	block_record.m_height = static_cast<unsigned int>(current_height);
	block_record.m_number_of_transactions = static_cast<unsigned int>(block.m_transaction.size());
	block_record.m_file_contains_block = block_base_filename.string();
	block_record.m_position_in_file = static_cast<int>(file_position_block_begin);
	block_record.m_size_of_binary_data = static_cast<unsigned int>(block_file.tellp()) - file_position_block_begin;
	
	save_current_height(block_record.m_height);
	save_block_record(block_record);
	// write last file number
	write_last_block_file_number(get_file_number_from_blk_path(block_base_filename));
	// write file information record
	save_file_information(file_number, block_absolute_filename);
}

c_transaction c_blockchain::get_transaction(const t_hash_type & txid) const {
	// read block_id for block contains transaction
	const std::string txid_as_str = container_to_string(txid);
	const std::string db_key = "t" + txid_as_str;
	std::string transaction_record_as_str;
	const auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &transaction_record_as_str);
	if (!status.ok()) 
		throw std::runtime_error("Read transaction record from db error(get_transaction): " + status.ToString());
	const c_transaction_record transaction_record = deserialize_from_string<c_transaction_record>(transaction_record_as_str);
	std::ifstream block_file(m_blocks_dir_path / transaction_record.m_file_contains_block, std::ios::binary | std::ios::in);
	const auto offset = transaction_record.m_offset_of_block + transaction_record.m_offset_of_transaction;
	block_file.seekg(offset);
	std::array<unsigned char, 4> size_of_tx_as_array;
	block_file.read(reinterpret_cast<char *>(size_of_tx_as_array.data()), size_of_tx_as_array.size());
	const uint32_t tx_size = get_integer<uint32_t>(size_of_tx_as_array);
	std::string tx_as_str(tx_size, '\0');
	block_file.read(tx_as_str.data(), static_cast<unsigned int>(tx_as_str.size()));
	c_transaction tx = deserialize_from_string<c_transaction>(tx_as_str);
	return tx;
}

bool c_blockchain::is_transaction_in_blockchain(const t_hash_type &txid) const {
		// read block_id for block contains transaction
		const std::string txid_as_str = container_to_string(txid);
		const std::string db_key = "t" + txid_as_str;
		std::string transaction_record_as_str;
		const auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &transaction_record_as_str);
		if (status.IsNotFound()) return false;
		else if(status.ok()) return true;
		else throw std::runtime_error("the database error: "+status.ToString());
}

size_t c_blockchain::get_number_of_blocks() const noexcept {
	return get_current_height() + 1; // +1 because genesis block has 0 height
}

c_block c_blockchain::get_block_at_height(const size_t height) const {
	const auto current_height = get_current_height();
	if (height > current_height)
		throw std::runtime_error("height " + std::to_string(height) + " > current blockchain height (" + std::to_string(current_height) + ")");
	// get file with block
	bool found_file = false;
	size_t lowest_file_number = 0;
	size_t upper_file_number = get_last_blockfile_number();
	size_t found_file_number = 0;
	// binary search
	c_file_info_record file_info_record;
	while (!found_file) {
		if (lowest_file_number == upper_file_number) found_file = true;
		const auto middle_file_number = static_cast<size_t>(lowest_file_number + (upper_file_number - lowest_file_number) / 2.);
		const std::string db_key = "f" + std::to_string(middle_file_number);
		std::string file_info_record_as_str;
		const auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &file_info_record_as_str);
		if (!status.ok()) 
			throw std::runtime_error("Load file info record from db error: " + status.ToString());
		file_info_record = deserialize_from_string<c_file_info_record>(file_info_record_as_str);
		if (file_info_record.m_height_lowest > height) upper_file_number = middle_file_number;
		else if (file_info_record.m_height_highest < height) lowest_file_number = middle_file_number;
		else {
			found_file = true;
			found_file_number = middle_file_number;
		}
		if (middle_file_number == lowest_file_number) lowest_file_number++;
		else if (middle_file_number == upper_file_number) upper_file_number--;
	}
	// findig block in file
	const auto filename = m_blocks_dir_path / get_block_filename(found_file_number);
	std::ifstream block_file(filename, std::ios::binary | std::ios::in);
	assert(block_file.good());
	const size_t index_in_file = height - file_info_record.m_height_lowest;
	for (size_t i = 0; i < index_in_file; i++) {
		std::array<unsigned char, 4> int_as_array;
		block_file.read(reinterpret_cast<char *>(int_as_array.data()), int_as_array.size()); // read 4 B of header size
		const uint32_t size_of_header = get_integer<uint32_t>(int_as_array);
		block_file.seekg(size_of_header, std::ios_base::cur); // skip header
		block_file.read(reinterpret_cast<char *>(int_as_array.data()), int_as_array.size()); // read 4 B of number transactions
		const uint32_t number_of_transactions = get_integer<uint32_t>(int_as_array);
		// skip transactions
		for (uint32_t j = 0; j < number_of_transactions; j++) {
			block_file.read(reinterpret_cast<char *>(int_as_array.data()), int_as_array.size()); // read 4 B of transaction size
			const uint32_t transaction_size = get_integer<uint32_t>(int_as_array);
			block_file.seekg(transaction_size, std::ios_base::cur); // skip transaction
		}
	}
	const auto block_proto = read_block_from_ifstream_proto(block_file);
	return block_from_protobuf(block_proto);
}

std::string c_blockchain::get_block_record_as_string(const t_hash_type& block_id) const {
	const std::string block_id_as_str = container_to_string(block_id);
	const std::string db_key = "b" + block_id_as_str;
	std::string block_record_as_str;
	const auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &block_record_as_str);
	if (!status.ok()) throw std::runtime_error("Load block record from db error: " + status.ToString());
	return block_record_as_str;
}

std::vector<c_block_record> c_blockchain::get_all_sorted_record_blocks(const size_t current_height) const {
	std::vector<c_block_record> all_blocks_record;
	all_blocks_record.reserve(current_height);
	std::unique_ptr<leveldb::Iterator> it(m_blocks_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice("b")); it->Valid(); it->Next()) {
		const auto status = it->status();
		if (!status.ok()) throw std::runtime_error("iterating db error: " + status.ToString());
		const auto db_key = it->key().ToString();
		if (db_key.front() != 'b') break;
		const auto &block_record_as_str = it->value().ToString();
		auto block_record = deserialize_from_string<c_block_record>(block_record_as_str);
		all_blocks_record.emplace_back(block_record);
	}
	std::sort(all_blocks_record.begin(), all_blocks_record.end(),
	[](const c_block_record & record_1, const c_block_record & record_2){return record_1.m_height > record_2.m_height;});
	return all_blocks_record;
}

std::vector<c_block_record> c_blockchain::get_sorted_record_blocks_with_txs_only() const {
	std::vector<c_block_record> blocks_record;
	std::unique_ptr<leveldb::Iterator> it(m_blocks_database->NewIterator(leveldb::ReadOptions()));
	for (it->Seek(leveldb::Slice("b")); it->Valid(); it->Next()) {
		const auto status = it->status();
		if (!status.ok()) throw std::runtime_error("iterating db error: " + status.ToString());
		const auto db_key = it->key().ToString();
		if (db_key.front() != 'b') break;
		const auto &block_record_as_str = it->value().ToString();
		auto block_record = deserialize_from_string<c_block_record>(block_record_as_str);
		if(block_record.m_number_of_transactions == 0) continue;
		else blocks_record.emplace_back(block_record);
	}
	std::sort(blocks_record.begin(), blocks_record.end(),
	[](const c_block_record & record_1, const c_block_record & record_2){return record_1.m_height > record_2.m_height;});
	return blocks_record;
}

c_block_record c_blockchain::get_block_record(const t_hash_type & block_id) const {
	const std::string block_record_as_str = get_block_record_as_string(block_id);
	c_block_record block_record = deserialize_from_string<c_block_record>(block_record_as_str);
	return block_record;
}

proto::block_record c_blockchain::get_block_record_proto(const t_hash_type & block_id) const {
	const std::string block_record_as_str = get_block_record_as_string(block_id);
	return deserialize_to_proto<proto::block_record>(block_record_as_str);
}

size_t c_blockchain::get_file_number_from_blk_path(const std::filesystem::path & block_filename) const {
	std::string filename = block_filename.string();
	filename.erase(filename.size() - std::string(".dat").size());
	filename.erase(0, filename.find_last_of("blk") + 1);
	return std::stoul(filename);
}

void c_blockchain::save_current_height(size_t height) {
	const std::string height_as_string = std::to_string(height);
	const std::string db_key = "h";
	const auto status = m_blocks_database->Put(leveldb::WriteOptions(), db_key, height_as_string);
	if (!status.ok()) throw std::runtime_error("Save current height to db error: " + status.ToString());
}

c_block c_blockchain::get_block_at_hash(const t_hash_type & block_id) const {
	const auto block_proto = get_block_at_hash_proto(block_id);
	return block_from_protobuf(block_proto);
}

proto::block c_blockchain::get_block_at_hash_proto(const t_hash_type & block_id) const {
	const auto block_record = get_block_record(block_id);
	// read from file
	const auto filename = m_blocks_dir_path / block_record.m_file_contains_block;
	std::ifstream block_file(filename, std::ios::binary | std::ios::in);
	block_file.seekg(block_record.m_position_in_file);
	const auto block_proto = read_block_from_ifstream_proto(block_file);
	return block_proto;
}

c_block c_blockchain::get_block_by_txid(const t_hash_type &txid) const {
	const std::string txid_as_str = container_to_string(txid);
	const std::string db_key = "t" + txid_as_str;
	std::string transaction_record_as_str;
	const auto status = m_blocks_database->Get(leveldb::ReadOptions(), db_key, &transaction_record_as_str);
	if (!status.ok()) throw std::runtime_error("Read transaction record from db error(get_block_by_txid): " + status.ToString());
	const c_transaction_record transaction_record = deserialize_from_string<c_transaction_record>(transaction_record_as_str);
	const auto block_id = transaction_record.m_block_id;
	const auto block = get_block_at_hash(block_id);
	return block;
}

std::vector<c_block> c_blockchain::get_blocks() const {
	const auto number_of_blocks = get_number_of_blocks();
	std::vector<c_block> blocks;
	blocks.reserve(number_of_blocks);
	for (size_t i = 0; i < number_of_blocks; i++) {
		auto block = get_block_at_height(i);
		blocks.emplace_back(std::move(block));
	}
	return blocks;
}

size_t c_blockchain::get_height_for_block_id(const t_hash_type & block_id) const {
	const auto block_record = get_block_record(block_id);
	return block_record.m_height;
}
