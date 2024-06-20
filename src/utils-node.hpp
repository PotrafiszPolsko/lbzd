#ifndef N_UTILS_NODE_HPP
#define N_UTILS_NODE_HPP

#include "main_module_builder.hpp"

namespace n_utils_node {

	std::unique_ptr<c_main_module> build_main_module(const boost::program_options::variables_map & vm);
	std::filesystem::path make_conf_file(const std::filesystem::path & datadir_path);
	std::filesystem::path get_default_datadir();
	void writing_string_to_a_file(const std::filesystem::path & filename_path, const std::string & text);
	std::string reading_string_to_a_file(const std::filesystem::path & filename_path);
	std::filesystem::path make_file(const std::filesystem::path & filename_path, const std::string & text);
	const std::string name_of_the_datadir = ".ivoting";
	const std::string name_of_the_file_tor_key = "private_key.pem";
	const std::string name_of_the_configuration_file = "ivoting.conf";

}

#endif
