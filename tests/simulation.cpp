#include <gtest/gtest.h>
#include <chrono>
#include "../src/simulation/simulation.hpp"

class simulation : public ::testing::TestWithParam<unsigned int> {
	public:
		const std::filesystem::path datadir_path = "./ivoting";
	void TearDown() override {
		std::filesystem::remove_all(datadir_path);
	}
	void SetUp() override {
		std::filesystem::remove_all(datadir_path);
	}
};

#ifdef COVERAGE_TESTS
      const unsigned int limit_to_paramtest_number_protocols = 2;
#elif IVOTING_TESTS
      const unsigned int limit_to_paramtest_number_protocols = 11;
#endif

INSTANTIATE_TEST_SUITE_P(variant_1, simulation, testing::Range(1u, limit_to_paramtest_number_protocols),
						 testing::PrintToStringParamName());
TEST_P(simulation, ) {
	const unsigned int number_of_protocol = GetParam();
	c_simulation sim(datadir_path, number_of_protocol);
	EXPECT_NO_THROW(sim.simulation_start());
}
