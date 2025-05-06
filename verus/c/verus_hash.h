#ifndef VERUS_HASH_H
#define VERUS_HASH_H

#include "common.h" // Include common definitions, including stddef.h for size_t

#ifdef __cplusplus
extern "C" {
#endif

// Hashes input `in` of length `len` into `out` (32 bytes).
// Implements VerusHash v1 algorithm (Haraka512-Zero + Sponge).
void verus_hash(unsigned char *out, const unsigned char *in, size_t len);

// Hashes input `in` of length `len` into `out` (32 bytes).
// Implements VerusHash v2.2 algorithm.
void verus_hash_v2(unsigned char *out, const unsigned char *in, size_t len);

// Initialization function is no longer needed as constants are baked in at compile time.

#ifdef __cplusplus
}
#endif
#endif /* VERUS_HASH_H */
