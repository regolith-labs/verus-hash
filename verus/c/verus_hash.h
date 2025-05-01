#ifndef VERUS_HASH_H
#define VERUS_HASH_H
#ifdef __cplusplus
extern "C" {
#endif

void verus_hash_32(unsigned char *out, const unsigned char *in, unsigned int len);

#ifdef __cplusplus
}
#endif
#endif /* VERUS_HASH_H */
