#ifndef BLOCKCHAIN_MODULE_BUILDER_HPP
#define BLOCKCHAIN_MODULE_BUILDER_HPP

#include "component_builder.hpp"
#include "blockchain_module.hpp"

class c_blockchain_module_builder : public c_component_builder {
	public:
		void set_program_options(const boost::program_options::variables_map & vm) override;
		std::unique_ptr<c_blockchain_module> get_result(c_mediator & mediator) const;
	private:
		boost::program_options::variables_map m_variable_map;
		std::unique_ptr<c_blockchain> build_blockchain() const;
		std::unique_ptr<c_utxo> build_utxo() const;
		std::unique_ptr<c_block_verifier> build_block_verifyer(const c_blockchain & blockchain, const c_utxo & utxo, size_t number_of_threads) const;
		std::unique_ptr<c_mempool> build_mempool() const;
};

#endif // BLOCKCHAIN_MODULE_BUILDER_HPP
