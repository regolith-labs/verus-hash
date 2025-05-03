/*───────────────────────────────────────────────────────────*
 *  haraka_portable.h  –  public API for the portable Haraka *
 *                       (desktop & Solana SBF/BPF)          *
 *───────────────────────────────────────────────────────────*/
#ifndef HARAKA_PORTABLE_H
#define HARAKA_PORTABLE_H

#include <stdint.h>     /* uint8_t / uint64_t */
#include <stddef.h>     /* size_t              */

#ifdef __cplusplus
extern "C" {
#endif

/* —―― tiny, libc-free memcpy / memset (exported) ――― */
void *verus_memcpy(void *dst, const void *src, size_t n);
void *verus_memset(void *dst, int c,          size_t n);

/* --- Safe 32-bit load/store helpers using verus_memcpy --- */
static inline uint32_t load_u32(const uint8_t *p)
{
    uint32_t v;
    verus_memcpy(&v, p, sizeof(v)); // Use verus_memcpy
    return v;
}

static inline void store_u32(uint8_t *p, uint32_t v)
{
    verus_memcpy(p, &v, sizeof(v)); // Use verus_memcpy
}

/* Tweak constants and Haraka-S sponge are now internal implementation details */

/* Public permutations with feed-forward (used by verus_hash.cpp) */
/* Note: These now use the static precomputed constants */
void haraka256_port(uint8_t *out, const uint8_t *in);
void haraka512_port(uint8_t *out, const uint8_t *in);

/* get_vrsc_constants is removed; generation now happens in build.rs */

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* HARAKA_PORTABLE_H */
