#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

#include <stdint.h> // Include for uint64_t etc.

#ifdef VERUS_BPF_TARGET
    // For BPF, provide a compatible definition for __m128i
    // This structure should be compatible with how _emu functions access it (e.g., casting to uint64_t*).
    typedef struct {
        uint64_t val[2]; // Two 64-bit values to make up 128 bits
    } __m128i_bpf_def;
    #define __m128i __m128i_bpf_def // Use our BPF-friendly type via macro
    typedef __m128i u128;

    // Define size_t for BPF if not available (usually it is via compiler builtins or other headers)
    // If errors persist related to size_t, this might need adjustment or a more specific BPF header.
    #ifndef _SIZE_T_DEFINED
    #define _SIZE_T_DEFINED
    typedef unsigned long size_t;
    #endif
    
    // Custom memory functions for BPF
    void *verus_memcpy(void *dest, const void *src, size_t n);
    void *verus_memset(void *s, int c, size_t n);

#else
    #include "immintrin.h" // Only include for non-BPF targets
    typedef __m128i u128;
    // For host, use standard library functions
    #include <string.h> // For memcpy, memset
    #define verus_memcpy memcpy
    #define verus_memset memset
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

typedef unsigned int uint32_t;

static inline __m128i _mm_unpacklo_epi32_emu(__m128i a, __m128i b)
{
    uint32_t result[4];
    uint32_t *tmp1 = (uint32_t *)&a, *tmp2 = (uint32_t *)&b;
    result[0] = tmp1[0];
    result[1] = tmp2[0];
    result[2] = tmp1[1];
    result[3] = tmp2[1];
    return *(__m128i *)result;
}

static inline __m128i _mm_unpackhi_epi32_emu(__m128i a, __m128i b)
{
    uint32_t result[4];
    uint32_t *tmp1 = (uint32_t *)&a, *tmp2 = (uint32_t *)&b;
    result[0] = tmp1[2];
    result[1] = tmp2[2];
    result[2] = tmp1[3];
    result[3] = tmp2[3];
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
