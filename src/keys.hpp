#ifndef KEYS_H
#define KEYS_H

#include <sodium.h>
#include <array>

struct c_keys {
    std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> m_key_receive;
    std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> m_key_transmit;
};


#endif // KEYS_H
