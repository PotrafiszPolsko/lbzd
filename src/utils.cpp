#include "utils.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>

uint64_t get_unix_time() {
	const auto now = boost::posix_time::second_clock::universal_time();
	const boost::posix_time::ptime epoch(boost::gregorian::date(1970, 1, 1));
	const auto duration = now - epoch;
	return static_cast<uint32_t>(duration.total_seconds());
}

void crypto_secure_random(void * const buff, size_t size) {
	if(sodium_init() < 0) {
		throw std::runtime_error("Sodium init error");
	}
	randombytes_buf(buff, size);
}

t_hash_type get_hash(const t_hash_type & input_1, const t_hash_type & input_2) noexcept {
	constexpr auto hash_size = std::tuple_size<t_hash_type>::value;
	t_hash_type hash;
	crypto_generichash_state state;
	crypto_generichash_init(&state, nullptr, 0, hash.size());
	if (input_1 < input_2) {
		crypto_generichash_update(&state, input_1.data(), hash_size);
		crypto_generichash_update(&state, input_2.data(), hash_size);
	} else {
		crypto_generichash_update(&state, input_2.data(), hash_size);
		crypto_generichash_update(&state, input_1.data(), hash_size);
	}
	crypto_generichash_final(&state, hash.data(), hash.size());
	return hash;
}
