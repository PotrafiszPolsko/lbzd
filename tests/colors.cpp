#include <gtest/gtest.h>
#include "../src/simulation/simulation.hpp"

class c_colors : public ::testing::TestWithParam<unsigned int> {
	public:
		const std::filesystem::path m_datadir_path = "./ivoting";
		const size_t m_number_of_voters_org_root = 100;
		const size_t m_number_of_voters_org_child = 10;
		const std::string m_co_key = "CO";
		const std::string m_cp_key = "CP";
		c_simulation m_simulation;

		void TearDown() override {
			std::filesystem::remove_all(m_datadir_path);
		}

		c_colors()
		    :
		      m_simulation(m_datadir_path)
		{

		}

		void test_find_CP_and_CO(const t_public_key_type & pk_root, const t_public_key_type & pk_child, size_t number_of_CO_and_CP) {
			const auto blocks = m_simulation.get_blockchain().get_blocks();
			size_t counter_of_actors_with_CO_child = 0;
			for(size_t i=0; i<blocks.size(); i++) {
				const auto transactions = blocks.at(i).m_transaction;
				for(const auto &tx:transactions) {
					const auto metadata_map = get_metadata_map(tx.m_allmetadata);
					const auto it_CP = metadata_map.find(m_cp_key);
					const auto it_CO = metadata_map.find(m_co_key);
					if(it_CP!=metadata_map.end() && it_CO!=metadata_map.end()) {
						const auto cp_value = it_CP->second;
						t_public_key_type cp_value_array;
						std::copy(cp_value.cbegin(), cp_value.cend(), cp_value_array.begin());
						EXPECT_EQ(pk_root, cp_value_array);

						const auto co_value = it_CO->second;
						t_public_key_type co_value_array;
						std::copy(co_value.cbegin(), co_value.cend(), co_value_array.begin());
						EXPECT_EQ(pk_child, co_value_array);
						counter_of_actors_with_CO_child++;
					}
				}
			}
			EXPECT_EQ(counter_of_actors_with_CO_child, number_of_CO_and_CP);
		}

		void test_find_CO_or_CP(const std::string & key, const t_public_key_type & pk, const size_t number_of_actors) {
			const auto blocks = m_simulation.get_blockchain().get_blocks();
			size_t counter_of_actors_with_key = 0;
			for(size_t i=0; i<blocks.size(); i++) {
				const auto transactions = blocks.at(i).m_transaction;
				for(const auto &tx:transactions) {
					const auto metadata_map = get_metadata_map(tx.m_allmetadata);
					const auto it_key = metadata_map.find(key);
					if(it_key!=metadata_map.end()){
						const auto key_value = it_key->second;
						t_public_key_type key_value_array;
						std::copy(key_value.cbegin(), key_value.cend(), key_value_array.begin());
						if(key_value_array == pk) counter_of_actors_with_key++;
					}
				}
			}
			EXPECT_EQ(counter_of_actors_with_key, number_of_actors); //+2 because the same color has issuer
		}

};

TEST_F(c_colors, this_same_color){
	auto organizer_root = m_simulation.get_organizer_root();
	const auto pk_organizer_root = organizer_root.get_pk();

	auto organizer_child = m_simulation.get_organizer_child();
	const auto pk_organizer_child = organizer_child.get_pk();

	m_simulation.mine_genesis_block();
	m_simulation.authorize_miner();
	auto miner = m_simulation.get_miner();

	m_simulation.authorize_organizer(miner);
	test_find_CO_or_CP(m_co_key, pk_organizer_root, 1);
	test_find_CO_or_CP(m_co_key, pk_organizer_child, 0);
	test_find_CP_and_CO(pk_organizer_root, pk_organizer_child, 0);
	test_find_CO_or_CP(m_cp_key, pk_organizer_root, 0);
	test_find_CO_or_CP(m_cp_key, pk_organizer_child, 0);

	m_simulation.authorize_issuer(miner);
	test_find_CO_or_CP(m_co_key, pk_organizer_root, 2);
	test_find_CO_or_CP(m_co_key, pk_organizer_child, 0);
	test_find_CP_and_CO(pk_organizer_root, pk_organizer_child, 0);
	test_find_CO_or_CP(m_cp_key, pk_organizer_root, 0);
	test_find_CO_or_CP(m_cp_key, pk_organizer_child, 0);

	m_simulation.authorize_voters(m_number_of_voters_org_root, miner);
	test_find_CO_or_CP(m_co_key, pk_organizer_root, m_number_of_voters_org_root + 2); //+2 because the same color with ONLY CO_key have issuer and organizer_root
	test_find_CO_or_CP(m_co_key, pk_organizer_child, 0);
	test_find_CP_and_CO(pk_organizer_root, pk_organizer_child, 0);
	test_find_CO_or_CP(m_cp_key, pk_organizer_root, 0);
	test_find_CO_or_CP(m_cp_key, pk_organizer_child, 0);

	m_simulation.authorize_organizer_by_organizer(miner);
	test_find_CO_or_CP(m_co_key, pk_organizer_root, m_number_of_voters_org_root + 2);
	test_find_CO_or_CP(m_co_key, pk_organizer_child, 1);
	test_find_CP_and_CO(pk_organizer_root, pk_organizer_child, 1);
	test_find_CO_or_CP(m_cp_key, pk_organizer_root, 1);
	test_find_CO_or_CP(m_cp_key, pk_organizer_child, 0);

	m_simulation.authorize_issuer_by_organizer_child(miner);
	test_find_CO_or_CP(m_co_key, pk_organizer_child, 2);
	test_find_CO_or_CP(m_co_key, pk_organizer_root, m_number_of_voters_org_root + 2);
	test_find_CP_and_CO(pk_organizer_root, pk_organizer_child, 1);
	test_find_CO_or_CP(m_cp_key, pk_organizer_root, 1);
	test_find_CO_or_CP(m_cp_key, pk_organizer_child, 0);

	m_simulation.authorize_existing_voters(m_number_of_voters_org_child, miner);
	test_find_CO_or_CP(m_co_key, pk_organizer_root, m_number_of_voters_org_root + 2);
	test_find_CO_or_CP(m_co_key, pk_organizer_child, m_number_of_voters_org_child + 2); //+2 because the same color with ONLY CO_key have issuer and organizer_child
	test_find_CP_and_CO(pk_organizer_root, pk_organizer_child, 1);
	test_find_CO_or_CP(m_cp_key, pk_organizer_root, 1);
	test_find_CO_or_CP(m_cp_key, pk_organizer_child, 0);

}
