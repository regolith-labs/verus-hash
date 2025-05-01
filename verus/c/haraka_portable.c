/*
 * haraka_portable.c  –  AES-free Haraka implementation for VerusHash
 *                      (minimal version for Solana BPF + desktop)
 */

#include <stdint.h>
#include <stddef.h>

#include "common.h"
#include "verus_clhash.h"
#include "haraka_portable.h"

/* ------------------------------------------------------------------ */
/*  Tiny memset that works without libc                               */
/* ------------------------------------------------------------------ */
// NOTE: No 'static inline' here, we provide the full definition below.
// The forward declaration is removed as the definition now comes first.
// Removed 'static' to match the non-static declaration in the header
// and allow external linkage (needed by stub common.cpp).
void *verus_memset(void *s, int c, size_t n)
{
    unsigned char *p = (unsigned char *)s;
    unsigned char uc = (unsigned char)c;
    for (size_t i = 0; i < n; ++i) p[i] = uc;
    return s;
}

/* make the compiler use OUR copy routine, not the builtin */
#define memset  verus_memset

/* ------------------------------------------------------------------ */
/*  Tiny memcpy that works without libc                               */
/* ------------------------------------------------------------------ */
static inline void verus_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
}

/* make the compiler use OUR copy routine, not the builtin */
#define memcpy  verus_memcpy 

/* ------------------------------------------------------------------ */
/*  Helpers that simulate SSE unpack instructions                     */
/* ------------------------------------------------------------------ */
static void unpacklo32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    verus_memcpy(tmp,      a,     4);
    verus_memcpy(tmp + 4,  b,     4);
    verus_memcpy(tmp + 8,  a + 4, 4);
    verus_memcpy(tmp + 12, b + 4, 4);
    verus_memcpy(t, tmp, 16);
}

static void unpackhi32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    verus_memcpy(tmp,      a + 8, 4);
    verus_memcpy(tmp + 4,  b + 8, 4);
    verus_memcpy(tmp + 8,  a + 12,4);
    verus_memcpy(tmp + 12, b + 12,4);
    verus_memcpy(t, tmp, 16);
}

/* ------------------------------------------------------------------ */
/*  Global round-constant buffers                                     */
/* ------------------------------------------------------------------ */
extern const unsigned char haraka_rc[40 * 16];
static unsigned char rc[40 * 16];
static unsigned char rc_sseed[40 * 16];

void load_constants_port(const unsigned char *sk,
                         const unsigned char *pk,
                          size_t               len)
{
    // Removed: unsigned char buf[40 * 16]; // Too large for SBF stack

    /* base constants - Copy directly first */
    verus_memcpy(rc, haraka_rc, 40 * 16);

    /* per-sk.seed constants - Generate directly into rc_sseed */
    if (sk != (void *)0) {
        // haraka_S(buf, 40 * 16, sk, len);
        // verus_memcpy(rc_sseed, buf, 40 * 16);
        haraka_S(rc_sseed, 40 * 16, sk, len); // Write directly
    }

    /* per-pk.seed constants - Generate directly into rc, overwriting base constants */
    // haraka_S(buf, 40 * 16, pk, len);
    // verus_memcpy(rc, buf, 40 * 16);
    haraka_S(rc, 40 * 16, pk, len); // Write directly
}

/* dummy xor-rounds (real tweak done by load_constants_port) */
static void haraka512_rc(unsigned char *s, const unsigned char *r)
{
    for (int i = 0; i < 64; ++i) s[i] ^= r[i];
}
static void haraka256_rc(unsigned char *s, const unsigned char *r)
{
    for (int i = 0; i < 32; ++i) s[i] ^= r[i];
}

/* ------------------------------------------------------------------ */
/*  Haraka-512  (64-byte in → 64-byte out)                            */
/* ------------------------------------------------------------------ */
void haraka512_port(unsigned char *out, const unsigned char *in)
{
    unsigned char s[64], tmp[16];

    verus_memcpy(s, in, 64);

    for (int r = 0; r < 5; ++r) {
        haraka512_rc(s, rc + r * 128);

        unpackhi32(tmp,  s,      s + 16);
        unpackhi32(s,    s + 32, s + 48);
        unpacklo32(s + 16, tmp,  s + 16);
        unpacklo32(s + 48, s,    s + 32);
        unpacklo32(s + 32, s + 16, s + 48);
        unpacklo32(s + 16, s + 48, tmp);
    }
    verus_memcpy(out, s, 64);
}

/* ------------------------------------------------------------------ */
/*  Haraka-256  (32-byte in → 32-byte out)                            */
/* ------------------------------------------------------------------ */
void haraka256_port(unsigned char *out, const unsigned char *in)
{
    unsigned char s[32], tmp[16];

    verus_memcpy(s, in, 32);

    for (int r = 0; r < 5; ++r) {
        haraka256_rc(s, rc + r * 128);

        unpacklo32(tmp, s, s + 16);
        unpackhi32(s + 16, s, s + 16);
        verus_memcpy(s, tmp, 16);
    }

    /* feed-forward */
    for (int i = 0; i < 32; ++i) s[i] ^= in[i];
    verus_memcpy(out, s, 32);
}

/* ------------------------------------------------------------------ */
/*  Sponge version used by VerusHash to derive constants              */
/* ------------------------------------------------------------------ */
void haraka_S(unsigned char *out, unsigned long long outlen,
              const unsigned char *in, unsigned long long inlen)
{
    unsigned char buf[64];

    while (inlen >= 32) {
        haraka256_port(buf, in);
        in    += 32;
        inlen -= 32;
    }

    /* last partial + padding */
    unsigned char t[32];
    verus_memset(t, 0, 32); // Explicitly zero the buffer using our function
    verus_memcpy(t, in, inlen);
    t[inlen] = 0x80;
    haraka256_port(buf, t);

    /* squeeze */
    unsigned long long pos = 0;
    while (pos < outlen) {
        unsigned long long clen = outlen - pos;
        if (clen > 32) clen = 32;

        verus_memcpy(out + pos, buf + 8, clen);   /* truncated */
        pos += clen;

        if (pos < outlen)
            haraka256_port(buf, buf);
    }
}
