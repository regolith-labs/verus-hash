#ifndef VERUS_COMMON_H
#define VERUS_COMMON_H
#include <stdint.h>

/* -------- very small helpers the portable code needs -------- */

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

#endif /* VERUS_COMMON_H */

