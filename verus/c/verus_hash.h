#ifndef VERUS_HASH_H
#define VERUS_HASH_H
#ifdef __cplusplus
extern "C" {
#endif

// Hashes input `in` of length `len` into `out` (32 bytes).
// Round constants are generated internally using the "VRSC" seed.
void verus_hash_v2(unsigned char *out, const unsigned char *in, unsigned int len);

// Initialization function - needed for host builds to link, even if empty.
void verus_hash_v2_init();

#ifdef __cplusplus
}
#endif
#endif /* VERUS_HASH_H */
