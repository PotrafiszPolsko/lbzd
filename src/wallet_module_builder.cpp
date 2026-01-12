#include "wallet_module_builder.hpp"
#include <filesystem>
#include <fstream>
#include "logger.hpp"
#include "seed.hpp"
#include "wallet_module.hpp"

void c_wallet_module_builder::set_program_options(const boost::program_options::variables_map & vm) {
	m_variable_map = vm;
}

std::unique_ptr<c_wallet_module_interface> c_wallet_module_builder::get_result(c_mediator &mediator) const {
	auto wallet_module = std::make_unique<c_wallet_module>(mediator);
	wallet_module->m_wallet = build_wallet();
	return wallet_module;
}

std::unique_ptr<c_wallet> c_wallet_module_builder::build_wallet() const {
	std::filesystem::path datadir_path = m_variable_map.at("datadir").as<std::filesystem::path>();
	auto seed_path = datadir_path;
	auto wallet_path = datadir_path;
	seed_path /= "wallet/seed";
	std::fstream result_file;
	if(!std::filesystem::exists(seed_path)) {
		return std::make_unique<c_wallet>(datadir_path);
	} else {
		result_file.open(seed_path, std::ios::binary | std::ios::in);
		std::array<unsigned char, n_seedparams::seed_number_of_entropy_bytes> entropy;
		result_file.read(reinterpret_cast<char*>(entropy.data()), entropy.size());
		return std::make_unique<c_wallet>(entropy, datadir_path);
	}
}
