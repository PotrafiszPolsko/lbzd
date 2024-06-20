#include <boost/program_options.hpp>
#include <sodium.h>
#include <google/protobuf/stubs/common.h>
#include "utils-node.hpp"

int main(int argc, char *argv[]) {
	if (sodium_init() < 0) {
		/* panic! the library couldn't be initialized, it is not safe to use */
		return 1;
	}
	// Verify that the version of the library that we linked against is
	// compatible with the version of the headers we compiled against.
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	
	namespace po = boost::program_options;
	po::options_description desc("Options");
	const auto default_datadir = n_utils_node::get_default_datadir();
	desc.add_options()
			("help", "produce help message")
			("datadir", po::value<std::filesystem::path>()->default_value(default_datadir), "Specify data directory")
			("bindaddress", po::value<std::string>()->default_value("0.0.0.0"), "Bind to given address and always listen on it")
			("bindport", po::value<unsigned short>()->default_value(n_networkparams::port_p2p_tcp), "Bind to given address and always listen on it")
			("onionport", po::value<unsigned short>()->default_value(n_networkparams::port_p2p_tor), "Hidden service port")
			("torcontrolport", po::value<unsigned short>()->default_value(9051), "Tor control port")
			("torsocksport", po::value<unsigned short>()->default_value(9050), "Tor SOCKS5 port")
			("addnode", po::value<std::vector<std::string>>()->multitoken(), "Add a node to connect. Format: <ip>:<port>")
			("enable-seed-node-connection", po::value<bool>()->default_value(true), "Enable connection to seed node")
			("portforwarder", po::value<bool>()->default_value(false), "Enable port forwarder")
			("externalip", po::value<std::string>(), "Specify your own public address (ip or url)")
			("rpc-tcp-address", po::value<std::string>()->default_value(std::string(n_rpcparams::address_rpc_tcp)), ("RPC address for TCP socket") )
			("rpc-tcp-port", po::value<uint16_t>()->default_value(n_rpcparams::port_rpc_tcp), ("RPC Port for TCP socket") )
			("rpcuser", po::value<std::string>()->default_value(""), "Username for JSON-RPC connections")
			("rpcpassword", po::value<std::string>()->default_value(""), "Password for JSON-RPC connections")
			("par", po::value<unsigned short>()->default_value(0), "Number of threads")
			("reindex-chainstate", po::value<bool>()->default_value(false), "Rebuild chain state from the currently indexed blocks")
			;
	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);
	const auto datadir = vm.at("datadir").as<std::filesystem::path>();
	const auto conf_file_path =n_utils_node::make_conf_file(datadir);
	if(std::filesystem::exists(conf_file_path)) {
		std::ifstream configfile(conf_file_path);
		po::store(po::parse_config_file(configfile , desc), vm);
		po::store(po::parse_command_line(argc, argv, desc), vm); // again because we want higher priority for commandline
		po::notify(vm);
	}
	if (vm.count("help")) {
		std::cout << desc << "\n";
		return 0;
	}
	auto main_module =n_utils_node::build_main_module(vm);
	main_module->run();
	return 0;

}
