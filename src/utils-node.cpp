#include "utils-node.hpp"
#include "conffile_text.hpp"

namespace n_utils_node {

std::unique_ptr<c_main_module> build_main_module(const boost::program_options::variables_map & vm) {
	c_main_module_builder main_module_builder;
	main_module_builder.set_program_options(vm);
	auto main_module = main_module_builder.get_result();
	return main_module;
}

void writing_string_to_a_file(const std::filesystem::path & filename_path, const std::string & text) {
	std::ofstream file(filename_path, std::ios::out);
	file << text;
	file.close();
}

std::string reading_string_to_a_file(const std::filesystem::path & filename_path) {
	std::ifstream file;
	file.open(filename_path, std::ios::in);
	std::string file_data;
	file >> file_data;
	file.close();
	return file_data;
}

std::filesystem::path make_file(const std::filesystem::path & filename_path, const std::string & text) {
	if(!std::filesystem::exists(filename_path)) writing_string_to_a_file(filename_path, text);
	return filename_path;
}

std::filesystem::path make_conf_file(const std::filesystem::path & datadir_path) {
	if(!std::filesystem::exists(datadir_path)) std::filesystem::create_directories(datadir_path);
	const auto path_to_the_configurtion_file = datadir_path / name_of_the_configuration_file;
	return make_file(path_to_the_configurtion_file, conffile_text);
}

std::filesystem::path get_default_datadir() {
	std::filesystem::path default_datadir_path;
	const auto * home_path = std::getenv("HOME");
	if(home_path == nullptr)
		throw std::runtime_error("there is no HOME env");
	default_datadir_path = home_path;
	default_datadir_path /= name_of_the_datadir;
	return default_datadir_path;
}

} // namespace
