#ifndef SPX_HARAKA_H
#define SPX_HARAKA_H

#include <stdint.h> // Include for uint64_t etc.

#ifdef VERUS_BPF_TARGET
    // For BPF, provide a compatible definition for __m128i
    typedef struct {
        uint64_t val[2]; // Two 64-bit values to make up 128 bits
    } __m128i_bpf_def;
    #define __m128i __m128i_bpf_def
    typedef __m128i u128;

    // Define size_t for BPF
    #ifndef _SIZE_T_DEFINED
    #define _SIZE_T_DEFINED
    typedef unsigned long size_t;
    #endif
    
    // Declare the actual implementations that are in haraka_portable.c
    // These need to be extern so the inline functions below can link to them.
    extern void *verus_memcpy(void *dest, const void *src, size_t n);
    extern void *verus_memset(void *s, int c, size_t n);
    extern int verus_memcmp(const void *s1, const void *s2, size_t n);

    // Define NULL if not already defined for BPF target
    #ifndef NULL
    #define NULL ((void*)0)
    #endif

    // Provide inline functions that call the actual implementations.
    // These effectively become the "memcpy" and "memset" for compilation units
    // including this header when VERUS_BPF_TARGET is defined.
    static inline void* memcpy(void* dest, const void* src, size_t n) {
        return verus_memcpy(dest, src, n);
    }
    static inline void* memset(void* s, int c, size_t n) {
        return verus_memset(s, c, n);
    }
#else
    // Host target: include standard headers and use standard functions
    #include "immintrin.h" 
    typedef __m128i u128;
    #include <string.h> // For standard memcpy, memset
    // Define verus_memcpy/memset as aliases to standard functions for host code
    // if it happens to call the verus_ prefixed versions.
    #define verus_memcpy memcpy
    #define verus_memset memset
#endif

#define NUMROUNDS 5

#ifdef _WIN32
typedef unsigned long long u64;
#else
typedef unsigned long u64;
#endif
// typedef __m128i u128; // u128 is already defined based on VERUS_BPF_TARGET

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
