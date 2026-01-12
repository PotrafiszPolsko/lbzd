#include <gtest/gtest.h>
#include "../src/utils-node.hpp"
#include "../src/words.hpp"
#include "../src/conffile_text.hpp"

TEST(utils_node, read_write_file) {
	std::string text_out;
	for(const auto &word:g_seed_all_words) std::copy(word.cbegin(), word.cend(), std::back_inserter(text_out));
	std::filesystem::path file_path = "./file";
	n_utils_node::writing_string_to_a_file(file_path, text_out);

	const std::string text_in = n_utils_node::reading_string_to_a_file(file_path);
	EXPECT_EQ(text_in, text_out);

	EXPECT_TRUE(std::filesystem::exists(file_path));
	std::filesystem::remove(file_path);
	n_utils_node::make_file(file_path, text_out);
	EXPECT_TRUE(std::filesystem::exists(file_path));
	std::filesystem::remove(file_path);
	EXPECT_FALSE(std::filesystem::exists(file_path));
}

TEST(utils_node, make_conf_file) {
	std::filesystem::path dir_path = "./";
	std::filesystem::path conf_file_path = dir_path;
	conf_file_path /= n_utils_node::name_of_the_configuration_file;
	n_utils_node::make_conf_file(dir_path);
	const std::string conf_file_str = n_utils_node::reading_string_to_a_file(conf_file_path);
	EXPECT_EQ(conf_file_str, conffile_text);
	std::filesystem::remove(conf_file_path);
}

TEST(utils_node, get_default_datadir) {
	const auto path_datadir_test = n_utils_node::get_default_datadir();
	std::filesystem::path path_datadir = std::getenv("HOME");
	path_datadir /= n_utils_node::name_of_the_datadir;
	EXPECT_EQ(path_datadir, path_datadir_test);
}
