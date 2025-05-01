#ifndef VERUS_COMMON_H
#define VERUS_COMMON_H
#include <stdint.h>
#include <stddef.h> // Include for size_t definition

/* -------- very small helpers the portable code needs -------- */

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

/* -------- Provide standard function declarations needed for SBF -------- */

// Declaration for memcpy. We will provide the implementation in a .c file.
void *memcpy(void *dest, const void *src, size_t n);

#endif /* VERUS_COMMON_H */

