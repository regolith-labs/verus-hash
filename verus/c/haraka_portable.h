#ifndef VERUS_HARAKA_PORTABLE_H
#define VERUS_HARAKA_PORTABLE_H
#include <stdint.h>

void haraka_S (unsigned char *out, unsigned long long outlen,
               const unsigned char *in, unsigned long long inlen);
void haraka256_port(unsigned char *out, const unsigned char *in);
void haraka512_port(unsigned char *out, const unsigned char *in);

/* exposed so verus_hash.cpp can tweak constants */
void load_constants_port(const unsigned char *sk,
                         const unsigned char *pk,
                         size_t len);

#endif /* VERUS_HARAKA_PORTABLE_H */
