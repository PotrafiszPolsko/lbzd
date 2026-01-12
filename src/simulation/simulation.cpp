#include "simulation.hpp"
#include "../params.hpp"
#include "../log.hpp"
#include "../logger.hpp"
#include <chrono>
#include <thread>

c_simulation::c_simulation(const std::filesystem::path & data_path, const size_t number_of_voting_protocols)
    :
m_adminsys(data_path),
	  m_blockchain(data_path),
	  m_utxo(data_path),
	  m_block_verifyer(m_blockchain, m_utxo, std::thread::hardware_concurrency()),
	  m_mempool(),
	  m_miner(),
	  m_adminsys_keypair(generate_adminsys_keypair()),
	  m_miner_keypair(generate_miner_keypair()),
	  m_organizer(),
      m_data_path(data_path)
{
	
	std::random_device rd;
	std::mt19937 gen(rd());
	std::string voting_protocol;
	for(size_t j=0; j<number_of_voting_protocols; j++) {
		for(size_t i=0; i<10; i++) {
			std::uniform_int_distribution<> distribution(0, 256);
			auto gen_char = distribution(gen);
			voting_protocol+=std::to_string(gen_char);
		}
		m_voting_protocols.push_back(voting_protocol);
		voting_protocol.erase();
	}
	LOG(info) << "Start simulation";
}

void c_simulation::mine_genesis_block() {
	LOG(info) << "mine genesis block";
	auto genesis_block = m_adminsys.mine_genesis_block();
	sign_block(genesis_block, m_adminsys_keypair);
	if (!m_block_verifyer.verify_block(genesis_block)) throw std::runtime_error("bad genesis block");
	LOG(info) << "add genesis block in to blockchain";
	m_blockchain.add_block(genesis_block);
	m_utxo.update(genesis_block);
}

void c_simulation::authorize_miner() {
	LOG(info) << "add authorize miner transaction to mempool";
	const auto miner_pk = m_miner_keypair.m_public_key;
	auto miner_auth_tx = m_adminsys.generate_miner_auth_tx(miner_pk);
	m_mempool.add_transaction(std::move(miner_auth_tx), m_utxo);
	// mine by adminsys because there is no other miners
	const auto prev_block = m_blockchain.get_last_block();
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)); // wait for next block
	auto block = m_adminsys.mine_block(prev_block, m_mempool);
	sign_block(block, m_adminsys_keypair);
	if (!m_block_verifyer.verify_block(block)) throw std::runtime_error("bad block");
	m_blockchain.add_block(block);
	assert(block.m_transaction.size()==1);
	m_utxo.update(block);
}

void c_simulation::authorize_organizer(c_miner &miner) {
	LOG(info) << "authorize organizer";
	const auto organizer_pk = m_organizer.get_pk();
	auto organizer_auth_tx = m_adminsys.generate_organizer_auth_tx(organizer_pk);
	m_mempool.add_transaction(std::move(organizer_auth_tx), m_utxo);
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)); // wait for next block
	mine_block(miner);
	const auto organizer_auth_tx_tmp = m_organizer.get_auth_tx_of_organizer(m_utxo, m_blockchain);
	if(organizer_auth_tx!=organizer_auth_tx_tmp) throw std::runtime_error("organizer auth tx is bad or is not added to blockchain");
}

void c_simulation::mine_block(c_miner &miner) {
	while (!m_mempool.empty()) {
		const auto last_block = m_blockchain.get_last_block();
		const auto number_of_active_miners = m_utxo.get_number_of_miners();
		auto block = miner.mine_block(last_block, number_of_active_miners, m_mempool);
		sign_block(block, m_miner_keypair);
		if (!m_block_verifyer.verify_block(block)) throw std::runtime_error("bad block");
		m_blockchain.add_block(block);
		m_utxo.update(block);
	}
}

void c_simulation::add_voting_protocol(const std::vector<unsigned char> &hash_voting_protocol, c_miner &miner) {
	auto tx_voting_protocol = m_organizer.add_voting_protocol(hash_voting_protocol);
	std::string txid_str;
	txid_str.resize(2*tx_voting_protocol.m_txid.size()+1);
	sodium_bin2hex(txid_str.data(), txid_str.size(), tx_voting_protocol.m_txid.data(), tx_voting_protocol.m_txid.size());
	LOG(info) << "txid of the results of hash voting protocol " << txid_str;
	m_mempool.add_transaction(std::move(tx_voting_protocol), m_utxo);
	std::this_thread::sleep_for(std::chrono::seconds(n_blockchainparams::blocks_diff_time_in_sec)); // wait for next block
	mine_block(miner);
}

c_miner &c_simulation::get_miner() {
	return m_miner;
}

c_organizer c_simulation::get_organizer() const {
	return m_organizer;
}

c_blockchain &c_simulation::get_blockchain() {
	return m_blockchain;
}

void c_simulation::reprocess_utxo() {
	LOG(info) << "Calculate reprocesing blockchain time";
	const auto number_of_blocks = m_blockchain.get_number_of_blocks();
	
	c_utxo utxo("./ivoting-utxo-reprocess-test");
	const auto start = std::chrono::steady_clock::now();
	for (size_t i = 0; i < number_of_blocks; i++) {
		const auto block = m_blockchain.get_block_at_height(i);
		utxo.update(block);
	}
	const auto stop = std::chrono::steady_clock::now();
	const auto diff_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
	LOG(info) << diff_time_ms << "ms";
}

void c_simulation::show_blockchain_summary() {
	LOG(info) << "Protocols results";
	const auto all_hashes_of_voting_protocols = m_utxo.get_hashes_of_voting_protocols();
	std::vector<t_hash_type> hashes_of_voting_protocols;
	for(auto &protocol:m_voting_protocols) {
		t_hash_type hash;
		crypto_generichash(hash.data(), hash.size(),
						   reinterpret_cast<unsigned char*>(protocol.data()), protocol.size(),
						   nullptr, 0);
		hashes_of_voting_protocols.emplace_back(hash);
	}
	size_t number_of_found_hashes = 0;
	for (const auto & hash : all_hashes_of_voting_protocols) {
		const auto it = std::find_if(hashes_of_voting_protocols.cbegin(), hashes_of_voting_protocols.cend(), [&hash](const t_hash_type & hash_of_voting_protocol){
			return hash==hash_of_voting_protocol;});
		if(it!=hashes_of_voting_protocols.cend()) number_of_found_hashes++;
	}

	size_t number_of_found_protocols = 0;
	size_t counter_of_txs_with_voting_protocol = 0;
	const auto number_of_blocks = m_blockchain.get_number_of_blocks();
	LOG(info) << "Number of blocks in blockchain " << number_of_blocks;
	size_t size_of_whole_blockchain = 0;
	for (size_t i = 0; i < number_of_blocks; i++) {
		const auto block = m_blockchain.get_block_at_height(i);
		const auto height = m_blockchain.get_height_for_block_id(block.m_header.m_actual_hash);
		if(i!=height) throw std::runtime_error("something wrong with the block_id and its height");
		const auto block_by_hash = m_blockchain.get_block_at_hash(block.m_header.m_actual_hash);
		if(block_by_hash!=block) throw std::runtime_error("something wrong with the block fetched by actual hash");
		std::vector<std::vector<t_hash_type>> merkle_branches;
		const auto block_size = size_of_block(block);
		size_of_whole_blockchain += block_size;
		LOG(info) << "Block " << i << " size: " << block_size << "B (" << static_cast<double>(block_size)/1024/1024 << "MB)";
		for(const auto &tx:block.m_transaction) {
			const auto block_by_txid = m_blockchain.get_block_by_txid(tx.m_txid);
			if(block_by_txid!=block) throw std::runtime_error("something wrong with the block fetched by txid");
			const auto merkle_branch = m_blockchain.get_merkle_branch(tx.m_txid);
			merkle_branches.push_back(merkle_branch);
			if(tx.m_type==t_transactiontype::another_voting_protocol) {
				counter_of_txs_with_voting_protocol++;
				const auto protocol = tx.m_allmetadata;
				const auto it = std::find_if(m_voting_protocols.cbegin(), m_voting_protocols.cend(), [&protocol](const std::string & voting_protocol) {
					const auto voting_protocol_vec = container_to_vector_of_uchars(voting_protocol);
					return protocol==voting_protocol_vec;});
				if(it!=m_voting_protocols.cend()) number_of_found_protocols++;
			}
		}
		auto it = std::adjacent_find(merkle_branches.cbegin(), merkle_branches.cend());
		if(it != merkle_branches.cend()) throw std::runtime_error("the same merkle branch");
	}
	LOG(info) << "Whole blockchain size: " << size_of_whole_blockchain << "B (" << static_cast<double>(size_of_whole_blockchain)/1024/1024 << "MB)";
	if((number_of_found_hashes==all_hashes_of_voting_protocols.size()) && (number_of_found_hashes==hashes_of_voting_protocols.size()))
		LOG(info) << "All hashes of voting protocols found in the utxo";
	else LOG(info) << "Not all hashes of voting protocols found in the utxo";
	if((number_of_found_protocols==counter_of_txs_with_voting_protocol) && (m_voting_protocols.size()==number_of_found_protocols))
		LOG(info) << "All voting protocols found in the blockchain";
	else LOG(info) << "Not all voting protocols found in the blockchain";
 }

void c_simulation::sign_block(c_block & block, const t_root_keypair & keypair) {
	const auto & block_hash = block.m_header.m_actual_hash;
	const auto block_signature = n_bip32::c_key_manager_BIP32::sign_root(block_hash.data(), block_hash.size(), keypair);
	block.m_header.m_all_signatures.push_back(block_signature);
}

t_root_keypair c_simulation::generate_adminsys_keypair() const {
	n_bip32::c_key_manager_BIP32 key_manager(n_blockchainparams::entropy_seed);
	return key_manager.get_root_key();
}

t_root_keypair c_simulation::generate_miner_keypair() const {
	n_bip32::c_key_manager_BIP32 key_manager;
	return key_manager.get_root_key();
}

void c_simulation::simulation_start() {
	mine_genesis_block();
	authorize_miner();
	if(!m_utxo.is_pk_miner(m_miner_keypair.m_public_key)) throw std::runtime_error("miner is not authorized");
	authorize_organizer(m_miner);
	if(!m_utxo.is_pk_organizer(m_organizer.get_pk())) throw std::runtime_error("organizer is not authorized");

	for(const auto &voting_protocol: m_voting_protocols){
		const auto voting_protocol_vec = container_to_vector_of_uchars(voting_protocol);
		const auto hash_voting_protocol = generate_hash(voting_protocol_vec);
		const auto hash_voting_protocol_vec = container_to_vector_of_uchars(hash_voting_protocol);
		add_voting_protocol(hash_voting_protocol_vec, m_miner);
	}
	show_blockchain_summary();

	c_log log(m_blockchain);
	log.write_in_log_file();
}
