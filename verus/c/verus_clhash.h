#ifndef VERUS_CLHASH_H
#define VERUS_CLHASH_H

#include <stdint.h>
#include <stddef.h>

/* --------------------------------------------------------------- */
/*  Minimal bits of CLHASH that the portable VerusHash needs       */
/* --------------------------------------------------------------- */

static const uint64_t CLHASH_K1 = 0x9e3779b185ebca87ULL;
static const uint64_t CLHASH_K2 = 0xc2b2ae3d27d4eb4fULL;

/* 32×32→64 multiply-xor mix (portable, no intrinsics) */
static inline uint64_t clmul_mix(uint64_t a, uint64_t b)
{
    uint64_t hi = (a >> 32) * (b >> 32);
    uint64_t lo = (uint32_t)a * (uint32_t)b;
    return hi ^ lo;
}

/* --------------------------------------------------------------- */
/*  Heap helpers: compiled **only** for native (non-BPF) targets    */
/* --------------------------------------------------------------- */
#if !defined(__SOLANA_BPF__) && !defined(SBF_SOLANA_SOLANA)
#include <stdlib.h>

static inline void *clhash_alloc(size_t n) { return malloc(n); }
static inline void  clhash_free (void *p)  { free(p);          }
#endif

#endif /* VERUS_CLHASH_H */
