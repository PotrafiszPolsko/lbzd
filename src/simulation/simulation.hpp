#ifndef C_SIMULATION_HPP
#define C_SIMULATION_HPP

#include "../adminsys.hpp"
#include "../blockchain.hpp"
#include "../block_verifier.hpp"
#include "../utxo.hpp"
#include "../organizer.hpp"
#include <random>

class c_simulation {
	public:
	    c_simulation(const std::filesystem::path & data_path, const size_t number_of_voting_protocols);
		void simulation_start();
		void mine_genesis_block();
		void authorize_miner();
		void authorize_organizer(c_miner &miner);
		c_miner &get_miner();
		c_organizer get_organizer() const;
		c_blockchain &get_blockchain();
	private:
		void mine_block(c_miner &miner);
		void add_voting_protocol(const std::vector<unsigned char> & hash_voting_protocol, c_miner &miner);
		c_adminsys m_adminsys;
		c_blockchain m_blockchain;
		c_utxo m_utxo;
		c_block_verifier m_block_verifyer;
		c_mempool m_mempool;
		c_miner m_miner;
		t_root_keypair m_adminsys_keypair;
		t_root_keypair m_miner_keypair;
		c_organizer m_organizer;
		std::filesystem::path m_data_path;
		std::vector<std::string> m_voting_protocols;
		
		void reprocess_utxo();
		void show_blockchain_summary();
		void sign_block(c_block & block, const t_root_keypair & keypair);
		t_root_keypair generate_adminsys_keypair() const;
		t_root_keypair generate_miner_keypair() const;
};

#endif // C_SIMULATION_HPP
