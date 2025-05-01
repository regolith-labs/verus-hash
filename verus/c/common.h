// Copyright (c) 2014 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_CRYPTO_COMMON_H
#define BITCOIN_CRYPTO_COMMON_H

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h"
#endif

#include <stdint.h>
// #include <assert.h> // Removed: Not available in SBF and not needed
// #include <string.h> // Removed: Not available in SBF, use haraka_portable.h declarations

#include "haraka_portable.h" // Include declarations for memcpy, memset, size_t

// #include "sodium.h" // Removed: Not available in SBF and not needed
// #include "compat/endian.h" // Removed: Not available in SBF, use builtins or portable implementations

// Define endian conversion functions if not provided by the environment (like SBF)
// These are simplified versions assuming little-endian target (like SBF)
#ifndef htole16
#define htole16(x) (x)
#endif
#ifndef le16toh
#define le16toh(x) (x)
#endif
#ifndef htole32
#define htole32(x) (x)
#endif
#ifndef le32toh
#define le32toh(x) (x)
#endif
#ifndef htole64
#define htole64(x) (x)
#endif
#ifndef le64toh
#define le64toh(x) (x)
#endif
#ifndef htobe16
static inline uint16_t htobe16(uint16_t x) { return (x >> 8) | (x << 8); }
#endif
#ifndef be16toh
#define be16toh(x) htobe16(x)
#endif
#ifndef htobe32
static inline uint32_t htobe32(uint32_t x) { return ((x & 0xFF) << 24) | ((x & 0xFF00) << 8) | ((x >> 8) & 0xFF00) | ((x >> 24) & 0xFF); }
#endif
#ifndef be32toh
#define be32toh(x) htobe32(x)
#endif
#ifndef htobe64
static inline uint64_t htobe64(uint64_t x) { return ((uint64_t)htobe32((uint32_t)x) << 32) | htobe32((uint32_t)(x >> 32)); }
#endif
#ifndef be64toh
#define be64toh(x) htobe64(x)
#endif


// #if defined(NDEBUG) // Removed: Assertions not used in SBF build
// # error "Zcash cannot be compiled without assertions."
// #endif

uint16_t static inline ReadLE16(const unsigned char* ptr)
{
    uint16_t x;
    verus_memcpy((char*)&x, ptr, 2);
    return le16toh(x);
}

uint32_t static inline ReadLE32(const unsigned char* ptr)
{
    uint32_t x;
    verus_memcpy((char*)&x, ptr, 4);
    return le32toh(x);
}

uint64_t static inline ReadLE64(const unsigned char* ptr)
{
    uint64_t x;
    verus_memcpy((char*)&x, ptr, 8);
    return le64toh(x);
}

void static inline WriteLE16(unsigned char* ptr, uint16_t x)
{
    uint16_t v = htole16(x);
    verus_memcpy(ptr, (char*)&v, 2);
}

void static inline WriteLE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htole32(x);
    verus_memcpy(ptr, (char*)&v, 4);
}

void static inline WriteLE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htole64(x);
    verus_memcpy(ptr, (char*)&v, 8);
}

uint32_t static inline ReadBE32(const unsigned char* ptr)
{
    uint32_t x;
    verus_memcpy((char*)&x, ptr, 4);
    return be32toh(x);
}

uint64_t static inline ReadBE64(const unsigned char* ptr)
{
    uint64_t x;
    verus_memcpy((char*)&x, ptr, 8);
    return be64toh(x);
}

void static inline WriteBE32(unsigned char* ptr, uint32_t x)
{
    uint32_t v = htobe32(x);
    verus_memcpy(ptr, (char*)&v, 4);
}

void static inline WriteBE64(unsigned char* ptr, uint64_t x)
{
    uint64_t v = htobe64(x);
    verus_memcpy(ptr, (char*)&v, 8);
}

// Removed init_and_check_sodium() function as it relies on libsodium and assert,
// which are not available or needed in the SBF environment.

/** Return the smallest number n such that (x >> n) == 0 (or 64 if the highest bit in x is set. */
uint64_t static inline CountBits(uint64_t x)
{
#ifdef HAVE_DECL___BUILTIN_CLZL
    if (sizeof(unsigned long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long) - __builtin_clzl(x) : 0;
    }
#endif
#ifdef HAVE_DECL___BUILTIN_CLZLL
    if (sizeof(unsigned long long) >= sizeof(uint64_t)) {
        return x ? 8 * sizeof(unsigned long long) - __builtin_clzll(x) : 0;
    }
#endif
    int ret = 0;
    while (x) {
        x >>= 1;
        ++ret;
    }
    return ret;
}

#endif // BITCOIN_CRYPTO_COMMON_H
