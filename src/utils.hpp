#ifndef UTILS_HPP
#define UTILS_HPP

#include <array>
#include <type_traits>
#include <sodium.h>
#include <vector>
#include <string_view>
#include <stdexcept>
#include <algorithm>
#include <string>
#include "types.hpp"

template<typename T, size_t N=sizeof(T)>
std::array<unsigned char, N> get_array_byte(T number) noexcept {
	static_assert(std::is_integral_v<T>);
	static_assert(sizeof(T) == N);
	std::array<unsigned char, N> array_of_uchar;
	for (std::size_t i = 0; i < N; i++)
		array_of_uchar[N - 1 - i] = static_cast<unsigned char>(number >> (i * 8));
	return array_of_uchar;
}



template<typename T, size_t N=sizeof(T)>
T get_integer(const std::array<unsigned char, N> & array) noexcept {
	static_assert(std::is_integral_v<T>);
	static_assert(sizeof(T) == N);
	T integer = 0;
	for (std::size_t i = 0; i < N; i++) {
		integer <<= 8;
		integer += static_cast<uint8_t>(array.at(i));
	}
	return integer;
}

template<typename T>
T get_integer(const std::vector<unsigned char> & vec) {
	static_assert(std::is_integral_v<T>);
	if (vec.size() != sizeof(T))
		throw std::invalid_argument("Bad vector size: " + std::to_string(vec.size()) + " vs " + std::to_string(sizeof(T)));
	T integer = 0;
	for (std::size_t i = 0; i < sizeof(T); i++) {
		integer <<= 8;
		integer += static_cast<uint8_t>(vec.at(i));
	}
	return integer;
}

template<typename T>
T get_integer(const std::string_view str) noexcept {
	std::vector<unsigned char> vec;
	std::copy(str.cbegin(), str.cend(), std::back_inserter(vec));
	return get_integer<T>(vec);
}

template<typename TContainer>
std::string container_to_string(const TContainer & container) {
	static_assert (std::is_same_v<typename TContainer::value_type, unsigned char>, "container must store unsigned char");
	std::string str;
	std::copy(container.cbegin(), container.cend(), std::back_inserter(str));
	return str;
}

template<typename TContainer>
std::vector<unsigned char> container_to_vector_of_uchars(const TContainer & container) {
	static_assert (std::is_same_v<typename TContainer::value_type, unsigned char> || std::is_same_v<typename TContainer::value_type, char>);
	std::vector<unsigned char> vec;
	std::copy(container.cbegin(), container.cend(), std::back_inserter(vec));
	return vec;
}

template<size_t N, typename TContainer>
std::array<unsigned char, N> container_to_array_of_uchars(const TContainer & container) {
	static_assert (std::is_same_v<typename TContainer::value_type, unsigned char>);
	std::array<unsigned char, N> arr;
	std::copy_n(container.cbegin(), N, arr.begin());
	return arr;
}

template<size_t N>
std::array<unsigned char, N> transform_string_to_array(const std::string & input) {
	if (input.size() != N) throw std::invalid_argument("bad input string size (input.size() == " + std::to_string(input.size()) + ")");
	std::array<unsigned char, N> out_array;
	std::copy( input.cbegin(), input.cend(), out_array.begin());
	return out_array;
}

template <size_t N>
std::array<unsigned char, crypto_generichash_BYTES> generate_hash(const std::array<unsigned char, N> & input) noexcept {
	std::array<unsigned char, crypto_generichash_BYTES> hash;
	crypto_generichash(hash.data(), hash.size(), input.data(), input.size(), nullptr, 0);
	return hash;
}

template<typename T>
std::array<unsigned char, crypto_generichash_BYTES> generate_hash(const std::vector<T> & input) {
	std::array<unsigned char, crypto_generichash_BYTES> hash;
	crypto_generichash(hash.data(), hash.size(), input.data(), input.size(), nullptr, 0);
	return hash;
}

uint64_t get_unix_time();
void crypto_secure_random(void * const buff, size_t size);


namespace std {
	template<> struct hash<t_hash_type> {
		size_t operator()(const t_hash_type & hash) const noexcept {
			size_t return_hash = 0;
			for (size_t i = 0; i < 4; i++) {
				return_hash += static_cast<uint8_t>(hash.at(i));
				return_hash <<= 8;
			}
			return return_hash;
		}
	};
} // namespace

namespace std {
	template<> struct hash<std::vector<unsigned char>> {
		size_t operator()(const std::vector<unsigned char> & hash) const noexcept {
			size_t return_hash = 0;
			for (size_t i = 0; i < 4; i++) {
				return_hash += static_cast<uint8_t>(hash.at(i));
				return_hash <<= 8;
			}
			return return_hash;
		}
	};
}

t_hash_type get_hash(const t_hash_type & input_1, const t_hash_type & input_2) noexcept;

#endif // UTILS_HPP
