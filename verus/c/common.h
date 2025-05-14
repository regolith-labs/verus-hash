// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#include <stdint.h>
// assert.h removed for BPF compatibility
// bitcoin-config.h removed for BPF compatibility

//#include "sodium.h"

#ifdef VERUS_BPF_TARGET
    // SBF target is little-endian.

    // Little-endian to host / host to little-endian are no-ops
    #define le16toh(x) ((uint16_t)(x))
    #define le32toh(x) ((uint32_t)(x))
    #define le64toh(x) ((uint64_t)(x))

    #define htole16(x) ((uint16_t)(x))
    #define htole32(x) ((uint32_t)(x))
    #define htole64(x) ((uint64_t)(x))

    // Big-endian to host / host to big-endian require byte swapping
    static inline uint16_t bpf_bswap16(uint16_t x) {
        return ((x >> 8) & 0xff) | ((x & 0xff) << 8);
    }

    static inline uint32_t bpf_bswap32(uint32_t x) {
        return ((x >> 24) & 0x000000ff) |
               ((x >>  8) & 0x0000ff00) |
               ((x <<  8) & 0x00ff0000) |
               ((x << 24) & 0xff000000);
    }

    static inline uint64_t bpf_bswap64(uint64_t x) {
        return ((x >> 56) & 0x00000000000000ffULL) |
               ((x >> 40) & 0x000000000000ff00ULL) |
               ((x >> 24) & 0x0000000000ff0000ULL) |
               ((x >>  8) & 0x00000000ff000000ULL) |
               ((x <<  8) & 0x000000ff00000000ULL) |
               ((x << 24) & 0x0000ff0000000000ULL) |
               ((x << 40) & 0x00ff000000000000ULL) |
               ((x << 56) & 0xff00000000000000ULL);
    }

    #define be16toh(x) bpf_bswap16(x) // Define even if not used by ReadBE16, for completeness
    #define be32toh(x) bpf_bswap32(x)
    #define be64toh(x) bpf_bswap64(x)

    #define htobe16(x) bpf_bswap16(x) // Define even if not used by WriteBE16
    #define htobe32(x) bpf_bswap32(x)
    #define htobe64(x) bpf_bswap64(x)

#else // Not VERUS_BPF_TARGET (host systems)
    #if defined(_WIN32) || defined(_WIN64)
        // This path is for Windows. If it's ever used, compat/endian.h would be needed.
        // The file compat/endian.h is not present in the project.
        // This could be an issue for Windows host builds if <endian.h> is not found
        // or if the compiler (like MSVC) doesn't provide <endian.h>.
        // MSVC provides _byteswap_ushort, _byteswap_ulong, _byteswap_uint64 in <stdlib.h>.
        // MinGW might provide <endian.h>.
        // For now, we keep the original logic which might require a "compat/endian.h" file.
        #include "compat/endian.h" 
    #elif defined(__APPLE__)
        #include <libkern/OSByteOrder.h>
        #define htobe16(x) OSSwapHostToBigInt16(x)
        #define htole16(x) OSSwapHostToLittleInt16(x)
        #define be16toh(x) OSSwapBigToHostInt16(x)
        #define le16toh(x) OSSwapLittleToHostInt16(x)
        #define htobe32(x) OSSwapHostToBigInt32(x)
        #define htole32(x) OSSwapHostToLittleInt32(x)
        #define be32toh(x) OSSwapBigToHostInt32(x)
        #define le32toh(x) OSSwapLittleToHostInt32(x)
        #define htobe64(x) OSSwapHostToBigInt64(x)
        #define htole64(x) OSSwapHostToLittleInt64(x)
        #define be64toh(x) OSSwapBigToHostInt64(x)
        #define le64toh(x) OSSwapLittleToHostInt64(x)
    #else
        #include <endian.h> // For Linux and other POSIX systems
    #endif
#endif

//#if defined(NDEBUG)
//# error "Bitcoin cannot be compiled without assertions."
//#endif

uint16_t static inline ReadLE16(const unsigned char* ptr)
{
    return le16toh(*((uint16_t*)ptr));
}

uint32_t static inline ReadLE32(const unsigned char* ptr)
{
    return le32toh(*((uint32_t*)ptr));
}

uint64_t static inline ReadLE64(const unsigned char* ptr)
{
    return le64toh(*((uint64_t*)ptr));
}

void static inline WriteLE16(unsigned char* ptr, uint16_t x)
{
    *((uint16_t*)ptr) = htole16(x);
}

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    *((uint32_t*)ptr) = htole32(x);
}

void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htole64(x);
}

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    return be32toh(*((uint32_t*)ptr));
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    return be64toh(*((uint64_t*)ptr));
}

void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    *((uint32_t*)ptr) = htobe32(x);
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htobe64(x);
}

/*int inline init_and_check_sodium()
{
    if (sodium_init() == -1) {
        return -1;
    }

    // What follows is a runtime test that ensures the version of libsodium
    // we're linked against checks that signatures are canonical (s < L).
    const unsigned char message[1] = { 0 };

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char sig[crypto_sign_BYTES];

    crypto_sign_keypair(pk, sk);
    crypto_sign_detached(sig, NULL, message, sizeof(message), sk);

    // assert(crypto_sign_verify_detached(sig, message, sizeof(message), pk) == 0); // Removed for BPF

    // Copied from libsodium/crypto_sign/ed25519/ref10/open.c
    // static const unsigned char L[32] = // Related code removed as it depends on assert and sodium
    //   { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    //     0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    //     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

    // Add L to S, which starts at sig[32].
    // unsigned int s = 0;
    // for (size_t i = 0; i < 32; i++) {
    //     s = sig[32 + i] + L[i] + (s >> 8);
    //     sig[32 + i] = s & 0xff;
    // }

    // assert(crypto_sign_verify_detached(sig, message, sizeof(message), pk) != 0); // Removed for BPF

    return 0;
}*/

#endif // BITCOIN_CRYPTO_COMMON_H
