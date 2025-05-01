#ifndef VERUS_HARAKA_PORTABLE_H
#define VERUS_HARAKA_PORTABLE_H
#include <stdint.h>
#include <stddef.h> // Include for size_t definition

// Define u128 as a struct of two uint64_t for portability
typedef struct {
    uint64_t low;
    uint64_t high;
} u128;


// Add extern "C" guards for C++ compatibility
#ifdef __cplusplus
extern "C" {
#endif

// Public interface
void haraka_S (unsigned char *out, unsigned long long outlen,
               const unsigned char *in, unsigned long long inlen);
void haraka256_port(unsigned char *out, const unsigned char *in);
void haraka512_port(unsigned char *out, const unsigned char *in);

// Function to tweak constants based on seeds (called by verus_hash_v2_init)
void tweak_constants(const unsigned char *pk_seed, const unsigned char *sk_seed,
                     unsigned long long seed_length);

// Keyed hash variant (if needed externally, otherwise could be static)
// Keep declaration for now, assuming it might be used later or by other C code.
void haraka512_port_keyed(unsigned char *out, const unsigned char *in, const u128 *rc);

// Declaration for the custom memset implementation in haraka_portable.c
// Needed by verus_hash.cpp and potentially stub common.cpp
void *verus_memset(void *s, int c, size_t n);
void *verus_memcpy(void *dest, const void *src, size_t n);


// Close extern "C" guards
#ifdef __cplusplus
}
#endif

#endif /* VERUS_HARAKA_PORTABLE_H */
