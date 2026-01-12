#include <iostream>
#include <sodium.h>
#include <boost/program_options.hpp>
#include "../blockchain.hpp"
#include "../wallet.hpp"
#include "../miner.hpp"
#include "../params.hpp"
#include "../adminsys.hpp"
#include "../block_verifier.hpp"
#include "../organizer.hpp"
#include "simulation.hpp"

int main(int argc, char *argv[]) {
	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		return 1;
	}
	namespace po = boost::program_options;
	po::options_description desc("Options");
	desc.add_options()
		("help", "produce help message")
		("simulation_variant1", "start simulation (10 voting protocols + check protocol in blockchain)")
		("simulation_variant2", "start simulation (100 voting protocols+ check protocol in blockchain)")
	;
	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	if (vm.count("help")) {
		std::cout << desc << "\n";
		return 0;
	}
	
	if (vm.count("simulation_variant1")) {
		c_simulation simulation("./ivoting", 10);
		simulation.simulation_start();
	} else if (vm.count("simulation_variant2")) {
		c_simulation simulation("./ivoting", 100);
		simulation.simulation_start();
	} else {
		std::cout << desc << "\n";
		return 0;
	}

	return 0;
}
