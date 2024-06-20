#include "peer_finder_mock.hpp"

c_peer_finder_mock::c_peer_finder_mock(const std::filesystem::path & datadir_path)
	:
      c_peer_finder(datadir_path)
{
}
