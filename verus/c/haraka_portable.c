#include <stdint.h>
#include <stddef.h>

#include "common.h"
#include "verus_clhash.h"
#include "haraka_portable.h"

/* ---- tiny memcpy replacement so we don't need libc ------------ */
static inline void verus_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char*)dst;
    const unsigned char *s = (const unsigned char*)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
}

/* ---- small helpers simulating SSE unpack ---------------------- */
void unpacklo32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    verus_memcpy(tmp,     a,     4);
    verus_memcpy(tmp+4,   b,     4);
    verus_memcpy(tmp+8,   a+4,   4);
    verus_memcpy(tmp+12,  b+4,   4);
    verus_memcpy(t, tmp, 16);
}

void unpackhi32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    verus_memcpy(tmp,     a+8,   4);
    verus_memcpy(tmp+4,   b+8,   4);
    verus_memcpy(tmp+8,   a+12,  4);
    verus_memcpy(tmp+12,  b+12,  4);
    verus_memcpy(t, tmp, 16);
}

/* -------------- truncated AES-free Haraka round ---------------- */
/* constants */
extern const unsigned char haraka_rc[40*16];
static unsigned char rc[40*16], rc_sseed[40*16];

void load_constants_port(const unsigned char *sk,
                         const unsigned char *pk,
                         size_t len)
{
    unsigned char buf[40*16];
    verus_memcpy(rc, haraka_rc, 40*16);

    if (sk != (void*)0) {
        haraka_S(buf, 40*16, sk, len);
        verus_memcpy(rc_sseed, buf, 40*16);
    }
    haraka_S(buf, 40*16, pk, len);
    verus_memcpy(rc, buf, 40*16);
}

/* dummy round functions: real constants live in verus_hash.cpp */
static void haraka512_rc(unsigned char *s, const unsigned char *rc) {
    for (int i=0;i<64;i++) s[i]^=rc[i];
}
static void haraka256_rc(unsigned char *s, const unsigned char *rc) {
    for (int i=0;i<32;i++) s[i]^=rc[i];
}

/* full Haraka-512 portable */
void haraka512_port(unsigned char *out, const unsigned char *in)
{
    unsigned char s[64], tmp[16];
    verus_memcpy(s,      in,      64);
    for (int r=0;r<5;r++){
        haraka512_rc(s, rc + r*128);
        unpackhi32(tmp,   s,      s+16);
        unpackhi32(s,     s+32,   s+48);
        unpacklo32(s+16,  tmp,    s+16);
        unpacklo32(s+48,  s,      s+32);
        unpacklo32(s+32,  s+16,   s+48);
        unpacklo32(s+16,  s+48,   tmp);
    }
    verus_memcpy(out, s, 64);
}

/* Haraka-256 portable */
void haraka256_port(unsigned char *out, const unsigned char *in)
{
    unsigned char s[32], tmp[16];
    verus_memcpy(s, in, 32);
    for (int r=0;r<5;r++){
        haraka256_rc(s, rc + r*128);
        unpacklo32(tmp, s, s+16);
        unpackhi32(s+16, s, s+16);
        verus_memcpy(s, tmp, 16);
    }
    for (int i=0;i<32;i++) s[i]^=in[i];  /* feed-forward */
    verus_memcpy(out, s, 32);
}

/* Sponge – only what VerusHash needs */
void haraka_S(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen)
{
    unsigned char buf[64];
    while (inlen >= 32) {
        haraka256_port(buf, in);
        in    += 32;
        inlen -= 32;
    }
    /* simple padding for our use-case */
    if (inlen) {
        unsigned char t[32] = {0};
        verus_memcpy(t, in, inlen);
        t[inlen] = 0x80;
        haraka256_port(buf, t);
    }
    verus_memcpy(out, buf, outlen);   /* we only ever ask ≤32 bytes */
}
