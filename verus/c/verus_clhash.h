#ifndef VERUS_CLHASH_H
#define VERUS_CLHASH_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  Minimal CLHASH subset required by portable VerusHash              */
/* ------------------------------------------------------------------ */

static const uint64_t CLHASH_K1 = 0x9e3779b185ebca87ULL;
static const uint64_t CLHASH_K2 = 0xc2b2ae3d27d4eb4fULL;

/* simple 64-bit multiply/xor mix, no intrinsics, no libc */
static inline uint64_t clmul_mix(uint64_t a, uint64_t b)
{
    uint64_t hi = (a >> 32) * (b >> 32);
    uint64_t lo = (uint32_t)a * (uint32_t)b;
    return hi ^ lo;
}

#endif /* VERUS_CLHASH_H */

