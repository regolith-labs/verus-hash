#ifndef VERUS_CLHASH_H
#define VERUS_CLHASH_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/*  Minimal CLHASH subset required by portable VerusHash              */
/* ------------------------------------------------------------------ */

static const uint64_t CLHASH_K1 = 0x9e3779b185ebca87ULL;
static const uint64_t CLHASH_K2 = 0xc2b2ae3d27d4eb4fULL;

/* Portable 64x64 carry-less multiplication returning lower 64 bits.
   This aims to replicate the behavior needed for the VerusHash v2.2 CLHASH step
   without using PCLMULQDQ intrinsics. */
static inline uint64_t clmul_mix(uint64_t a, uint64_t b) {
    uint64_t a_lo = (uint32_t)a;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = (uint32_t)b;
    uint64_t b_hi = b >> 32;

    uint64_t p0 = 0, p1 = 0; // p2 (a_hi * b_hi) is not needed for lower 64 bits result

    // Calculate p0 = a_lo * b_lo (lower 64 bits of 128-bit result)
    // Uses simple shift-and-xor loop for GF(2) multiplication
    uint64_t x = a_lo;
    for (int i = 0; i < 32; ++i) {
        if ((b_lo >> i) & 1) {
            p0 ^= (x << i);
        }
    }

    // Calculate p1 = a_lo * b_hi + a_hi * b_lo
    uint64_t t1 = 0;
    x = a_lo;
    for (int i = 0; i < 32; ++i) {
        if ((b_hi >> i) & 1) {
            t1 ^= (x << i);
        }
    }
    uint64_t t2 = 0;
    x = a_hi;
    for (int i = 0; i < 32; ++i) {
        if ((b_lo >> i) & 1) {
            t2 ^= (x << i);
        }
    }
    p1 = t1 ^ t2;

    // Combine results for lower 64 bits: result_lo64 = (p1 << 32) ^ p0
    return (p1 << 32) ^ p0;
}

#endif /* VERUS_CLHASH_H */

