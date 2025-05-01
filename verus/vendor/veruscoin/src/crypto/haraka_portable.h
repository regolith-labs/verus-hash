#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

#include <stdint.h> // For uint types
// #include <string.h> // Removed: Not available in SBF, rely on compiler builtins for memcpy

// Define size_t and declare static memcpy/memset/memcmp for SBF environment
// Making them static ensures they have internal linkage, matching the definitions
// in haraka_portable.c and avoiding linker conflicts.
typedef unsigned long size_t; // Note: Solana SDK might provide its own size_t
static void *memcpy(void *dest, const void *src, size_t n);
static void *memset(void *s, int c, size_t n);
static int memcmp(const void *s1, const void *s2, size_t n);

#ifdef VERUSHASH_PORTABLE
  // Define a compatible type for __m128i when using portable C code
  // Requires C11 or later for alignas, which should be fine with modern clang.
  #include <stdalign.h>
  typedef struct {
      alignas(16) unsigned char bytes[16];
  } __m128i;
#elif defined(__arm__) || defined(__aarch64__)
  #include "crypto/sse2neon.h"
#elif !defined(VERUSHASH_PORTABLE) // Explicitly check if not portable before including x86 headers
  #include "immintrin.h"
#endif

#define NUMROUNDS 5

#ifdef _WIN32
typedef unsigned long long u64;
#else
typedef unsigned long u64;
#endif
typedef __m128i u128;

extern void aesenc(unsigned char *s, const unsigned char *rk);

#define AES2_EMU(s0, s1, rci) \
  aesenc((unsigned char *)&s0, (unsigned char *)&(rc[rci])); \
  aesenc((unsigned char *)&s1, (unsigned char *)&(rc[rci + 1])); \
  aesenc((unsigned char *)&s0, (unsigned char *)&(rc[rci + 2])); \
  aesenc((unsigned char *)&s1, (unsigned char *)&(rc[rci + 3]));

// Unused function. Triggers a shift-count-overflow warning on gcc 8 and above when cross compiling for aarch64
/*
static inline void mix2_emu(__m128i *s0, __m128i *s1)
{
    __m128i tmp;
    tmp = (*s0 & 0xffffffff) | ((*s1 & 0xffffffff) << 32) | ((*s0 & 0xffffffff00000000) << 32) | ((*s1 & 0xffffffff00000000) << 64);
    *s1 = ((*s0 >> 64) & 0xffffffff) | (((*s1 >> 64) & 0xffffffff) << 32) | (((*s0 >> 64) & 0xffffffff00000000) << 32) | (((*s1 >> 64) & 0xffffffff00000000) << 64);
    *s0 = tmp;
}
*/

// typedef unsigned int uint32_t; // Remove redundant typedef, use stdint.h

static inline __m128i _mm_unpacklo_epi32_emu(__m128i a, __m128i b)
{
    // Use memcpy for type safety when __m128i is a struct/array
    uint32_t result[4];
    unsigned char *bytes_a = (unsigned char *)&a;
    unsigned char *bytes_b = (unsigned char *)&b;
    memcpy(&result[0], bytes_a, 4);      // a[0]
    memcpy(&result[1], bytes_b, 4);      // b[0]
    memcpy(&result[2], bytes_a + 4, 4);  // a[1]
    memcpy(&result[3], bytes_b + 4, 4);  // b[1]
    // Original logic (assuming direct uint32_t access):
    // uint32_t *tmp1 = (uint32_t *)&a, *tmp2 = (uint32_t *)&b;
    // result[0] = tmp1[0];
    // result[1] = tmp2[0];
    // result[2] = tmp1[1];
    // result[3] = tmp2[1];
    // result[2] = tmp1[1]; // Erroneous leftover code
    // result[3] = tmp2[1]; // Erroneous leftover code
    return *(__m128i *)result;
}

static inline __m128i _mm_unpackhi_epi32_emu(__m128i a, __m128i b)
{
    // Use memcpy for type safety when __m128i is a struct/array
    uint32_t result[4];
    unsigned char *bytes_a = (unsigned char *)&a;
    unsigned char *bytes_b = (unsigned char *)&b;
    memcpy(&result[0], bytes_a + 8, 4);  // a[2]
    memcpy(&result[1], bytes_b + 8, 4);  // b[2]
    memcpy(&result[2], bytes_a + 12, 4); // a[3]
    memcpy(&result[3], bytes_b + 12, 4); // b[3]
    // Original logic (assuming direct uint32_t access):
    // uint32_t *tmp1 = (uint32_t *)&a, *tmp2 = (uint32_t *)&b;
    // result[0] = tmp1[2];
    // result[1] = tmp2[2];
    // result[2] = tmp1[3];
    // result[3] = tmp2[3];
    return *(__m128i *)result;
}

#define MIX2_EMU(s0, s1) \
  tmp = _mm_unpacklo_epi32_emu(s0, s1); \
  s1 = _mm_unpackhi_epi32_emu(s0, s1); \
  s0 = tmp;

/* load constants */
void load_constants_port();

/* Tweak constants with seed */
void tweak_constants(const unsigned char *pk_seed, const unsigned char *sk_seed, 
	                 unsigned long long seed_length);

/* Haraka Sponge */
void haraka_S(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen);

/* Applies the 512-bit Haraka permutation to in. */
void haraka512_perm(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-512 */
void haraka512_port(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-512 */
void haraka512_port_keyed(unsigned char *out, const unsigned char *in, const u128 *rc);

/* Applies the 512-bit Haraka permutation to in, using zero key. */
void haraka512_perm_zero(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-512, using zero key */
void haraka512_port_zero(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 */
void haraka256_port(unsigned char *out, const unsigned char *in);

/* Implementation of Haraka-256 using sk.seed constants */
void haraka256_sk(unsigned char *out, const unsigned char *in);

#endif
