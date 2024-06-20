#include <sodium.h>
#include "blockchain_synchronizer.hpp"
#include <boost/program_options.hpp>
#include <iostream>

int main(int argc, char *argv[]) {
	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		return 1;
	}
	namespace po = boost::program_options;
	po::options_description desc("Options");
	desc.add_options()
			("help", "produce help message")
			("ip", po::value<std::string>()->required()->default_value("127.0.0.1"), "ip address of sending node")
	;
	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	if (vm.count("help")) {
		std::cout << desc << "\n";
		return 0;
	}
	const std::string ip_str = vm["ip"].as<std::string>();
	const auto ip = boost::asio::ip::address_v4::from_string(ip_str);

	c_blockchain blockchain;
	c_utxo utxo;
	c_block_verifier block_verifyer(blockchain, utxo);
	c_blockchain_synchronizer synchronizer(blockchain, block_verifyer, utxo);
	synchronizer.receive_blockchain(ip);
	return 0;
}