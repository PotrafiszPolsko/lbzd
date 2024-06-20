#include "blockchain_module_builder.hpp"
#include "logger.hpp"

void c_blockchain_module_builder::set_program_options(const boost::program_options::variables_map & vm) {
	m_variable_map = vm;
}

std::unique_ptr<c_blockchain_module> c_blockchain_module_builder::get_result(c_mediator & mediator) const {
	auto blockchain_module = std::make_unique<c_blockchain_module>(mediator);
	blockchain_module->m_blockchain = build_blockchain();
	blockchain_module->m_utxo = build_utxo();
	auto number_of_threads = m_variable_map.at("par").as<unsigned short>();
	if(number_of_threads == 0) number_of_threads = static_cast<unsigned short>(std::thread::hardware_concurrency());
	blockchain_module->m_block_verifyer = build_block_verifyer(*(blockchain_module->m_blockchain), *(blockchain_module->m_utxo), number_of_threads);
	blockchain_module->m_mempool = build_mempool();
	assert(blockchain_module->m_utxo != nullptr);
	if (m_variable_map.at("reindex-chainstate").as<bool>()) {
		blockchain_module->reindex_chainstate();
	}
	return blockchain_module;
}

std::unique_ptr<c_blockchain> c_blockchain_module_builder::build_blockchain() const {
	const std::filesystem::path datadir_path = m_variable_map.at("datadir").as<std::filesystem::path>();
	auto blockchain = std::make_unique<c_blockchain>(datadir_path);
	return blockchain;
}

std::unique_ptr<c_utxo> c_blockchain_module_builder::build_utxo() const {
	if (m_variable_map.at("reindex-chainstate").as<bool>()) {
		const std::filesystem::path datadir_path = m_variable_map.at("datadir").as<std::filesystem::path>();
		std::filesystem::remove_all(datadir_path/"chainstate");
	}
	const std::filesystem::path datadir_path = m_variable_map.at("datadir").as<std::filesystem::path>();
	auto utxo = std::make_unique<c_utxo>(datadir_path);
	return utxo;
}

std::unique_ptr<c_block_verifier> c_blockchain_module_builder::build_block_verifyer(const c_blockchain & blockchain, const c_utxo & utxo,
																					size_t number_threads) const {
	if(number_threads==0) number_threads = std::thread::hardware_concurrency();
	auto block_verifyer = std::make_unique<c_block_verifier>(blockchain, utxo, number_threads);
	return block_verifyer;
}

std::unique_ptr<c_mempool> c_blockchain_module_builder::build_mempool() const {
	auto mempool = std::make_unique<c_mempool>();
	return mempool;
}
