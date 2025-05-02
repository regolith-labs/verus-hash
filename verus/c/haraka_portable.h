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

/* Tweak constants and Haraka-S sponge are now internal implementation details */

/* Public permutations with feed-forward (used by verus_hash.cpp) */
/* Note: These now build constants internally on the stack */
void haraka256_port(uint8_t *out, const uint8_t *in);

/* --- Helper for build-time constant generation (host only) --- */
/* get_vrsc_constants is removed; generation now happens in build.rs */
void haraka512_port(uint8_t *out, const uint8_t *in);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* HARAKA_PORTABLE_H */
