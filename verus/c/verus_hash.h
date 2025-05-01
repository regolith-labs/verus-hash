#ifndef VERUS_HASH_H
#define VERUS_HASH_H
#ifdef __cplusplus
extern "C" {
#endif

void verus_hash_v2(unsigned char *out, const unsigned char *in, unsigned int len);
void verus_hash_v2_init();

#ifdef __cplusplus
}
#endif
#endif /* VERUS_HASH_H */
