#ifndef VERUS_UINT256_H
#define VERUS_UINT256_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint64_t v[4]; } uint256;

/* minimal subset used by verus_hash.cpp */
static inline void u256_from_le(uint256 *r, const unsigned char *in)
{
    for (size_t i = 0; i < 4; ++i) {
        r->v[i] =
            ((uint64_t)in[i*8+0])       |
            ((uint64_t)in[i*8+1] <<  8) |
            ((uint64_t)in[i*8+2] << 16) |
            ((uint64_t)in[i*8+3] << 24) |
            ((uint64_t)in[i*8+4] << 32) |
            ((uint64_t)in[i*8+5] << 40) |
            ((uint64_t)in[i*8+6] << 48) |
            ((uint64_t)in[i*8+7] << 56);
    }
}

#endif /* VERUS_UINT256_H */

