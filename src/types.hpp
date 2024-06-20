#ifndef TYPES_HPP
#define TYPES_HPP

#include <array>
#include <sodium.h>
#include <vector>
#include <string>

using t_hash_type = std::array<unsigned char, crypto_generichash_BYTES>;
constexpr size_t hash_size = std::tuple_size<t_hash_type>::value;
using t_signature_type = std::array<unsigned char, crypto_sign_BYTES>;
constexpr size_t signature_size = std::tuple_size<t_signature_type>::value;
constexpr size_t seed_bytes = 32;
using t_seed_type = std::array<unsigned char, seed_bytes>;
constexpr size_t nonce_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
using t_nonce_type = std::array<unsigned char, nonce_size>;

struct t_secret_key_type {
	std::array<unsigned char, 32> m_kl; // left 32B of k (modifyted bytes)
	std::array<unsigned char, 32> m_kr; // right 32B of k
};

using t_public_key_type = std::array<unsigned char, 32>; // A
constexpr size_t public_key_size = std::tuple_size<t_public_key_type>::value;

struct t_voting_metadata {
	std::string m_name;
	uint8_t m_voting_type; //0=secret, 1=open
	std::string m_question;
	std::vector<std::string> m_options;
	uint16_t m_number_of_choice; // number of choices in multiple choice questions
	uint32_t m_authorization_level;
	uint32_t m_number_of_blocks_to_the_end;
	uint32_t m_start_timepoint;
};

bool operator==(const t_voting_metadata & lhs, const t_voting_metadata & rhs) noexcept;

using t_authorization_level = uint32_t;

#endif // TYPES_HPP
