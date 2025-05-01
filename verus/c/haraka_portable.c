/*
 *  haraka_portable.c  ─  portable (non-AES-NI) Haraka used by VerusHash
 *                        – works on desktop and Solana SBF/BPF.
 *
 *  2025-05  •  single translation unit  •  no libc calls  •  stack-safe (<512 B)
 */

#include "haraka_portable.h"
#include "common.h"                 /* upstream typedefs/macros */

/*─────────────────────────────────────────────────────────────*/
/*  tiny memcpy / memset (avoid pulling libc)                  */
/*─────────────────────────────────────────────────────────────*/
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
#define memcpy verus_memcpy
#define memset verus_memset

/*─────────────────────────────────────────────────────────────*/
/*  AES S-box (verbatim from upstream)                         */
/*─────────────────────────────────────────────────────────────*/
static const unsigned char sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/*─────────────────────────────────────────────────────────────*/
/*  run-time generated AES T-tables (4 × 256 × 4 B)            */
/*─────────────────────────────────────────────────────────────*/
#define SAES_WPOLY 0x011b
static uint32_t saes_table[4][256];          /* BSS-zeroed               */

static inline uint8_t f2(uint8_t x) { return (uint8_t)((x<<1) ^ (((x>>7)&1)*SAES_WPOLY)); }
static inline uint8_t f3(uint8_t x) { return (uint8_t)(f2(x) ^ x); }

/*─────────────────────────────────────────────────────────────*/
/*  Haraka round-constants (verbatim)                          */
/*─────────────────────────────────────────────────────────────*/
#include "haraka_constants.c"                 /* → haraka_rc[40][16] */

static unsigned char rc[40][16];       /* working copy            */
static unsigned char rc_sseed[40][16]; /* for sk.seed tweaking    */

/*─────────────────────────────────────────────────────────────*/
/*  one-time constructor: build tables + copy RC              */
/*─────────────────────────────────────────────────────────────*/
__attribute__((constructor))
static void haraka_init(void)
{
    /* 1) build T-tables */
    for (int p = 0; p < 256; ++p) {
        uint8_t s = sbox[p];
        saes_table[0][p] = ((uint32_t)f3(s)      ) |
                           ((uint32_t)   s <<  8) |
                           ((uint32_t)   s << 16) |
                           ((uint32_t)f2(s) << 24);
        saes_table[1][p] = ((uint32_t)f2(s)      ) |
                           ((uint32_t)f3(s) <<  8) |
                           ((uint32_t)   s << 16) |
                           ((uint32_t)   s << 24);
        saes_table[2][p] = ((uint32_t)   s       ) |
                           ((uint32_t)f2(s) <<  8) |
                           ((uint32_t)f3(s) << 16) |
                           ((uint32_t)   s << 24);
        saes_table[3][p] = ((uint32_t)   s       ) |
                           ((uint32_t)   s <<  8) |
                           ((uint32_t)f2(s) << 16) |
                           ((uint32_t)f3(s) << 24);
    }
    /* 2) copy reference constants */
    memcpy(rc, haraka_rc, 40 * 16);
}

/*─────────────────────────────────────────────────────────────*/
/*  full AESENC round (table version)                          */
/*─────────────────────────────────────────────────────────────*/
static void aesenc(unsigned char *s, const unsigned char *rk)
{
    const uint32_t *t = saes_table[0];

    uint32_t x0 = ((uint32_t *)s)[0], x1 = ((uint32_t *)s)[1],
             x2 = ((uint32_t *)s)[2], x3 = ((uint32_t *)s)[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8;  t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8;  t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8;  t += 256;

    y0 ^= t[x3]; y1 ^= t[x0]; y2 ^= t[x1]; y3 ^= t[x2];

    ((uint32_t*)s)[0] = y0 ^ ((const uint32_t*)rk)[0];
    ((uint32_t*)s)[1] = y1 ^ ((const uint32_t*)rk)[1];
    ((uint32_t*)s)[2] = y2 ^ ((const uint32_t*)rk)[2];
    ((uint32_t*)s)[3] = y3 ^ ((const uint32_t*)rk)[3];
}

/*─────────────────────────────────────────────────────────────*/
/*  SIMD-unpack helpers (byte shuffles)                        */
/*─────────────────────────────────────────────────────────────*/
static void unpacklo32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    memcpy(tmp,      a,     4);
    memcpy(tmp + 4,  b,     4);
    memcpy(tmp + 8,  a + 4, 4);
    memcpy(tmp + 12, b + 4, 4);
    memcpy(t, tmp, 16);
}
static void unpackhi32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    memcpy(tmp,      a + 8,  4);
    memcpy(tmp + 4,  b + 8,  4);
    memcpy(tmp + 8,  a + 12, 4);
    memcpy(tmp + 12, b + 12, 4);
    memcpy(t, tmp, 16);
}

/*─────────────────────────────────────────────────────────────*/
/*  tweak_constants (VerusHash)                                */
/*─────────────────────────────────────────────────────────────*/
void tweak_constants(const unsigned char *pk_seed,
                     const unsigned char *sk_seed,
                     unsigned long long   seed_len)
{
    static unsigned char buf[40 * 16];   /* 640 B – static */

    memcpy(rc, haraka_rc, 40 * 16);

    if (sk_seed) {
        haraka_S(buf, 40 * 16, sk_seed, seed_len);
        memcpy(rc_sseed, buf, 40 * 16);
    }
    haraka_S(buf, 40 * 16, pk_seed, seed_len);
    memcpy(rc, buf, 40 * 16);
}

/*─────────────────────────────────────────────────────────────*/
/*  Haraka sponge helpers                                      */
/*─────────────────────────────────────────────────────────────*/
#define HARAKAS_RATE 32

static void haraka512_perm(unsigned char *out, const unsigned char *in); /* fwd */

static void haraka_S_absorb(unsigned char *s, unsigned r,
                            const unsigned char *m, unsigned long long mlen,
                            unsigned char pad)
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
    tmp[mlen]  = pad;
    tmp[r-1]  |= 0x80;
    for (unsigned i = 0; i < r; ++i) s[i] ^= tmp[i];
}

static void haraka_S_squeeze(unsigned char *out, unsigned blocks,
                             unsigned char *s, unsigned r)
{
    while (blocks--) {
        haraka512_perm(s, s);
        memcpy(out, s, r);
        out += r;
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

/*─────────────────────────────────────────────────────────────*/
/*  global scratch                                             */
/*─────────────────────────────────────────────────────────────*/
static unsigned char scratch512[64];
static unsigned char scratch256[32];
static unsigned char scratch16 [16];

/*─────────────────────────────────────────────────────────────*/
/*  Haraka-512 permutation + feed-forward                      */
/*─────────────────────────────────────────────────────────────*/
static void haraka512_perm(unsigned char *out, const unsigned char *in)
{
    unsigned char *s   = scratch512;
    unsigned char *tmp = scratch16;

    memcpy(s,      in,     16);
    memcpy(s + 16, in + 16,16);
    memcpy(s + 32, in + 32,16);
    memcpy(s + 48, in + 48,16);

    for (unsigned r = 0; r < 5; ++r) {
        for (unsigned j = 0; j < 2; ++j) {
            aesenc(s,       rc[4*r*2 + 4*j    ]);
            aesenc(s + 16,  rc[4*r*2 + 4*j + 1]);
            aesenc(s + 32,  rc[4*r*2 + 4*j + 2]);
            aesenc(s + 48,  rc[4*r*2 + 4*j + 3]);
        }
        unpacklo32(tmp,     s,      s + 16);
        unpackhi32(s,       s,      s + 16);
        unpacklo32(s + 16,  s + 32, s + 48);
        unpackhi32(s + 32,  s + 32, s + 48);
        unpacklo32(s + 48,  s,      s + 32);
        unpackhi32(s,       s,      s + 32);
        unpackhi32(s + 32,  s + 16, tmp);
        unpacklo32(s + 16,  s + 16, tmp);
    }
    memcpy(out, s, 64);
}

void haraka512_port(unsigned char *out, const unsigned char *in)
{
    unsigned char *buf = scratch512;

    haraka512_perm(buf, in);
    for (unsigned i = 0; i < 64; ++i) buf[i] ^= in[i];

    memcpy(out,       buf +  8, 8);
    memcpy(out +  8,  buf + 24, 8);
    memcpy(out + 16,  buf + 32, 8);
    memcpy(out + 24,  buf + 48, 8);
}

/*─────────────────────────────────────────────────────────────*/
/*  Haraka-256                                                 */
/*─────────────────────────────────────────────────────────────*/
void haraka256_port(unsigned char *out, const unsigned char *in)
{
    unsigned char *s   = scratch256;
    unsigned char *tmp = scratch16;

    memcpy(s,      in,     16);
    memcpy(s + 16, in + 16,16);

    for (unsigned r = 0; r < 5; ++r) {
        for (unsigned j = 0; j < 2; ++j) {
            aesenc(s,       rc[2*r*2 + 2*j    ]);
            aesenc(s + 16,  rc[2*r*2 + 2*j + 1]);
        }
        unpacklo32(tmp,   s,      s + 16);
        unpackhi32(s + 16,s,      s + 16);
        memcpy(s, tmp, 16);
    }
    for (unsigned i = 0; i < 32; ++i) out[i] = in[i] ^ s[i];
}

/* eof */
