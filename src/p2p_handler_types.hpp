#ifndef P2P_HANDLER_TYPES_HPP
#define P2P_HANDLER_TYPES_HPP

#include <functional>
#include "span.hpp"
#include "peer_reference.hpp"

using read_handler = std::function<void(const c_peer_reference &, span<const unsigned char>)>;
using new_peer_handler = std::function<void(const c_peer_reference &)>;

#endif // P2P_HANDLER_TYPES_HPP
