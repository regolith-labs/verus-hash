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

/* —―― optional key-tweak (used by VerusHash) ――― */
void tweak_constants(const uint8_t *pk_seed,
                     const uint8_t *sk_seed,
                     uint64_t       seed_len);

/* The “Haraka-S” sponge (only needed for tweak_constants) */
void haraka_S(uint8_t       *out, uint64_t outlen,
              const uint8_t *in,  uint64_t inlen);

/* Public permutations with feed-forward (used by verus_hash.cpp) */
void haraka256_port(uint8_t *out, const uint8_t *in);
void haraka512_port(uint8_t *out, const uint8_t *in);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* HARAKA_PORTABLE_H */
