/*
 * haraka_portable.c  –  AES-free Haraka implementation
 *                      usable on desktop **and** Solana SBF.
 *
 * 2025-05 – single-unit, no libc calls, SBF-stack-safe.
 */

#include "haraka_portable.h"
#include "common.h"          /* upstream helper macros / typedefs */

/* ────────────────────────────────────────────────────────── */
/*  tiny memcpy / memset                                     */
/* ────────────────────────────────────────────────────────── */
inline void *verus_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char       *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}
inline void *verus_memset(void *p, int c, size_t n)
{
    unsigned char *d = (unsigned char *)p;
    unsigned char  v = (unsigned char)c;
    for (size_t i = 0; i < n; ++i) d[i] = v;
    return p;
}

/*  use them locally                                                */
#define memcpy verus_memcpy
#define memset verus_memset

/* ────────────────────────────────────────────────────────── */
/*  portable AES round (unchanged from upstream)             */
/* ────────────────────────────────────────────────────────── */
#define XT(x) (((x)<<1) ^ ((((x)>>7)&1) * 0x1b))

static const unsigned char sbox[256] = {
  /* 256-byte table omitted for brevity – unchanged – */
#include "sbox.inc"
};

static void aesenc_port(unsigned char *s, const unsigned char *rk)
{
    unsigned char v[4][4], t, u;

    for (unsigned i = 0; i < 16; ++i)
        v[i & 3][(i >> 2) ^ (i & 3)] = sbox[s[i]];

    for (unsigned i = 0; i < 4; ++i) {
        t = v[i][0];
        u = v[i][0] ^ v[i][1] ^ v[i][2] ^ v[i][3];
        v[i][0] ^= u ^ XT(v[i][0] ^ v[i][1]);
        v[i][1] ^= u ^ XT(v[i][1] ^ v[i][2]);
        v[i][2] ^= u ^ XT(v[i][2] ^ v[i][3]);
        v[i][3] ^= u ^ XT(v[i][3] ^ t);
    }
    for (unsigned i = 0; i < 16; ++i)
        s[i] = v[i & 3][i >> 2] ^ rk[i];
}

/* ────────────────────────────────────────────────────────── */
/*  SSE unpack helpers                                        */
/* ────────────────────────────────────────────────────────── */
static void unpacklo32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    memcpy(tmp,       a,     4);
    memcpy(tmp + 4,   b,     4);
    memcpy(tmp + 8,   a + 4, 4);
    memcpy(tmp + 12,  b + 4, 4);
    memcpy(t, tmp, 16);
}
static void unpackhi32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    memcpy(tmp,       a + 8, 4);
    memcpy(tmp + 4,   b + 8, 4);
    memcpy(tmp + 8,   a +12, 4);
    memcpy(tmp + 12,  b +12, 4);
    memcpy(t, tmp, 16);
}

/* ────────────────────────────────────────────────────────── */
/*  round constants                                           */
/* ────────────────────────────────────────────────────────── */
#include "haraka_constants.c"              /* 40×16 reference */

static unsigned char rc[40][16];           /* working copy   */
static unsigned char rc_sseed[40][16];     /* for sk.seed    */

/*  public helper for VerusHash                                */
void tweak_constants(const unsigned char *pk_seed,
                     const unsigned char *sk_seed,
                     unsigned long long   seed_len)
{
    static unsigned char buf[40 * 16];     /* 640 B – static! */

    memcpy(rc, haraka_rc, 40*16);

    if (sk_seed) {
        haraka_S(buf, 40*16, sk_seed, seed_len);
        memcpy(rc_sseed, buf, 40*16);
    }
    haraka_S(buf, 40*16, pk_seed, seed_len);
    memcpy(rc, buf, 40*16);
}

/* ────────────────────────────────────────────────────────── */
/*  Sponge helpers                                            */
/* ────────────────────────────────────────────────────────── */
#define HARAKAS_RATE 32

static void haraka512_perm(unsigned char *out,
                           const unsigned char *in);   /* fwd */

static void haraka_S_absorb(unsigned char *s, unsigned r,
                            const unsigned char *m, unsigned long long mlen,
                            unsigned char p)
{
    unsigned char tmp[HARAKAS_RATE];

    while (mlen >= r) {
        for (unsigned i = 0; i < r; ++i) s[i] ^= m[i];
        haraka512_perm(s, s);
        m    += r;
        mlen -= r;
    }
    memset(tmp, 0, sizeof tmp);
    memcpy(tmp, m, mlen);
    tmp[mlen]   = p;
    tmp[r-1]   |= 0x80;
    for (unsigned i = 0; i < r; ++i) s[i] ^= tmp[i];
}

static void haraka_S_squeeze(unsigned char *h, unsigned nblocks,
                             unsigned char *s, unsigned r)
{
    while (nblocks--) {
        haraka512_perm(s, s);
        memcpy(h, s, r);
        h += r;
    }
}

void haraka_S(unsigned char *out, unsigned long long outlen,
              const unsigned char *in,  unsigned long long inlen)
{
    unsigned char state[64] = {0};
    unsigned char tmp[32];

    haraka_S_absorb(state, HARAKAS_RATE, in, inlen, 0x1F);

    haraka_S_squeeze(out, outlen / 32, state, HARAKAS_RATE);
    out += (outlen / 32) * 32;

    if (outlen & 31) {
        haraka_S_squeeze(tmp, 1, state, HARAKAS_RATE);
        memcpy(out, tmp, outlen & 31);
    }
}

/* ────────────────────────────────────────────────────────── */
/*  Scratch buffers (GLOBAL – so they don’t hit the stack)    */
/* ────────────────────────────────────────────────────────── */
static unsigned char scratch512[64];   /* used by perm + ff */
static unsigned char scratch256[32];
static unsigned char scratch16 [16];

/* ────────────────────────────────────────────────────────── */
/*  Haraka-512 permutation                                    */
/* ────────────────────────────────────────────────────────── */
static void haraka512_perm(unsigned char *out, const unsigned char *in)
{
    unsigned char *s   = scratch512;   /* 64 B */
    unsigned char *tmp = scratch16;    /* 16 B */

    memcpy(s,       in,      16);
    memcpy(s + 16,  in + 16, 16);
    memcpy(s + 32,  in + 32, 16);
    memcpy(s + 48,  in + 48, 16);

    for (unsigned r = 0; r < 5; ++r) {
        for (unsigned j = 0; j < 2; ++j) {
            aesenc_port(s,       rc[4*r*2 + 4*j    ]);
            aesenc_port(s + 16,  rc[4*r*2 + 4*j + 1]);
            aesenc_port(s + 32,  rc[4*r*2 + 4*j + 2]);
            aesenc_port(s + 48,  rc[4*r*2 + 4*j + 3]);
        }

        unpacklo32(tmp,      s,      s + 16);
        unpackhi32(s,        s,      s + 16);
        unpacklo32(s + 16,   s + 32, s + 48);
        unpackhi32(s + 32,   s + 32, s + 48);
        unpacklo32(s + 48,   s,      s + 32);
        unpackhi32(s,        s,      s + 32);
        unpackhi32(s + 32,   s + 16, tmp);
        unpacklo32(s + 16,   s + 16, tmp);
    }
    memcpy(out, s, 64);
}

void haraka512_port(unsigned char *out, const unsigned char *in)
{
    unsigned char *buf = scratch512;

    haraka512_perm(buf, in);
    for (unsigned i = 0; i < 64; ++i) buf[i] ^= in[i];

    memcpy(out,      buf +  8, 8);
    memcpy(out +  8, buf + 24, 8);
    memcpy(out + 16, buf + 32, 8);
    memcpy(out + 24, buf + 48, 8);
}

/* ────────────────────────────────────────────────────────── */
/*  Haraka-256                                               */
/* ────────────────────────────────────────────────────────── */
void haraka256_port(unsigned char *out, const unsigned char *in)
{
    unsigned char *s   = scratch256;   /* 32 B */
    unsigned char *tmp = scratch16;    /* 16 B */

    memcpy(s,       in,      16);
    memcpy(s + 16,  in + 16, 16);

    for (unsigned r = 0; r < 5; ++r) {
        for (unsigned j = 0; j < 2; ++j) {
            aesenc_port(s,       rc[2*r*2 + 2*j    ]);
            aesenc_port(s + 16,  rc[2*r*2 + 2*j + 1]);
        }
        unpacklo32(tmp, s, s + 16);
        unpackhi32(s + 16, s, s + 16);
        memcpy(s, tmp, 16);
    }
    for (unsigned i = 0; i < 32; ++i) out[i] = in[i] ^ s[i];
}

/* eof */
