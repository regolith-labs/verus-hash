#ifndef VERUS_COMMON_H
#define VERUS_COMMON_H
#include <stdint.h>
#include <stddef.h> // Include for size_t definition

/* -------- very small helpers the portable code needs -------- */

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

/* -------- Provide standard function declarations needed for SBF -------- */

// No standard memcpy declaration here to avoid conflicts.
// We use a macro in haraka_portable.c to redirect calls internally.

#endif /* VERUS_COMMON_H */

