/*--------------------------------------------------------------------
 * haraka_portable.c  –  portable (non-AES-NI) Haraka for VerusHash
 *                       usable on both desktop and Solana SBF/BPF.
 *  – no libc, no dynamic allocation
 *  – stack-safe (≤ 512 B)
 *------------------------------------------------------------------*/

#include "haraka_portable.h"
#include "common.h"               /* upstream typedefs (u128, etc.)   */

/*──────────────────────────────────────────────────────────────────*/
/*  tiny memcpy / memset                                            */
/*──────────────────────────────────────────────────────────────────*/
static inline void *verus_memcpy(void *d, const void *s, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        ((unsigned char *)d)[i] = ((const unsigned char *)s)[i];
    return d;
}
static inline void *verus_memset(void *p, int c, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        ((unsigned char *)p)[i] = (unsigned char)c;
    return p;
}
#define memcpy  verus_memcpy
#define memset  verus_memset

/*──────────────────────────────────────────────────────────────────*/
/*  compile-time AES “T” tables (exact upstream maths)              */
/*──────────────────────────────────────────────────────────────────*/
#define SAES_WPOLY 0x011b
#define saes_f2(x) ((x<<1) ^ ((((x)>>7)&1)*SAES_WPOLY))
#define saes_f3(x) (saes_f2(x) ^ (x))
#define saes_b2w(b0,b1,b2,b3) (((uint32_t)(b3)<<24)|((uint32_t)(b2)<<16)|\
                               ((uint32_t)(b1)<<8)|(b0))
#define saes_u0(p) saes_b2w(saes_f2(p),       p,       p, saes_f3(p))
#define saes_u1(p) saes_b2w(saes_f3(p), saes_f2(p),    p,       p)
#define saes_u2(p) saes_b2w(       p , saes_f3(p), saes_f2(p),   p)
#define saes_u3(p) saes_b2w(       p ,       p , saes_f3(p), saes_f2(p))

#define saes_data(w) {\
    w(0x63),w(0x7c),w(0x77),w(0x7b),w(0xf2),w(0x6b),w(0x6f),w(0xc5),\
    w(0x30),w(0x01),w(0x67),w(0x2b),w(0xfe),w(0xd7),w(0xab),w(0x76),\
    w(0xca),w(0x82),w(0xc9),w(0x7d),w(0xfa),w(0x59),w(0x47),w(0xf0),\
    w(0xad),w(0xd4),w(0xa2),w(0xaf),w(0x9c),w(0xa4),w(0x72),w(0xc0),\
    w(0xb7),w(0xfd),w(0x93),w(0x26),w(0x36),w(0x3f),w(0xf7),w(0xcc),\
    w(0x34),w(0xa5),w(0xe5),w(0xf1),w(0x71),w(0xd8),w(0x31),w(0x15),\
    w(0x04),w(0xc7),w(0x23),w(0xc3),w(0x18),w(0x96),w(0x05),w(0x9a),\
    w(0x07),w(0x12),w(0x80),w(0xe2),w(0xeb),w(0x27),w(0xb2),w(0x75),\
    w(0x09),w(0x83),w(0x2c),w(0x1a),w(0x1b),w(0x6e),w(0x5a),w(0xa0),\
    w(0x52),w(0x3b),w(0xd6),w(0xb3),w(0x29),w(0xe3),w(0x2f),w(0x84),\
    w(0x53),w(0xd1),w(0x00),w(0xed),w(0x20),w(0xfc),w(0xb1),w(0x5b),\
    w(0x6a),w(0xcb),w(0xbe),w(0x39),w(0x4a),w(0x4c),w(0x58),w(0xcf),\
    w(0xd0),w(0xef),w(0xaa),w(0xfb),w(0x43),w(0x4d),w(0x33),w(0x85),\
    w(0x45),w(0xf9),w(0x02),w(0x7f),w(0x50),w(0x3c),w(0x9f),w(0xa8),\
    w(0x51),w(0xa3),w(0x40),w(0x8f),w(0x92),w(0x9d),w(0x38),w(0xf5),\
    w(0xbc),w(0xb6),w(0xda),w(0x21),w(0x10),w(0xff),w(0xf3),w(0xd2),\
    w(0xcd),w(0x0c),w(0x13),w(0xec),w(0x5f),w(0x97),w(0x44),w(0x17),\
    w(0xc4),w(0xa7),w(0x7e),w(0x3d),w(0x64),w(0x5d),w(0x19),w(0x73),\
    w(0x60),w(0x81),w(0x4f),w(0xdc),w(0x22),w(0x2a),w(0x90),w(0x88),\
    w(0x46),w(0xee),w(0xb8),w(0x14),w(0xde),w(0x5e),w(0x0b),w(0xdb),\
    w(0xe0),w(0x32),w(0x3a),w(0x0a),w(0x49),w(0x06),w(0x24),w(0x5c),\
    w(0xc2),w(0xd3),w(0xac),w(0x62),w(0x91),w(0x95),w(0xe4),w(0x79),\
    w(0xe7),w(0xc8),w(0x37),w(0x6d),w(0x8d),w(0xd5),w(0x4e),w(0xa9),\
    w(0x6c),w(0x56),w(0xf4),w(0xea),w(0x65),w(0x7a),w(0xae),w(0x08),\
    w(0xba),w(0x78),w(0x25),w(0x2e),w(0x1c),w(0xa6),w(0xb4),w(0xc6),\
    w(0xe8),w(0xdd),w(0x74),w(0x1f),w(0x4b),w(0xbd),w(0x8b),w(0x8a),\
    w(0x70),w(0x3e),w(0xb5),w(0x66),w(0x48),w(0x03),w(0xf6),w(0x0e),\
    w(0x61),w(0x35),w(0x57),w(0xb9),w(0x86),w(0xc1),w(0x1d),w(0x9e),\
    w(0xe1),w(0xf8),w(0x98),w(0x11),w(0x69),w(0xd9),w(0x8e),w(0x94),\
    w(0x9b),w(0x1e),w(0x87),w(0xe9),w(0xce),w(0x55),w(0x28),w(0xdf),\
    w(0x8c),w(0xa1),w(0x89),w(0x0d),w(0xbf),w(0xe6),w(0x42),w(0x68),\
    w(0x41),w(0x99),w(0x2d),w(0x0f),w(0xb0),w(0x54),w(0xbb),w(0x16) }

static const uint32_t saes_table[4][256] =
        { saes_data(saes_u0), saes_data(saes_u1),
          saes_data(saes_u2), saes_data(saes_u3) };

/*──────────────────────────────────────────────────────────────────*/
/*  software aesenc (mix-columns + add-rk)                          */
/*──────────────────────────────────────────────────────────────────*/
static void aesenc(unsigned char *s, const unsigned char *rk)
{
    const uint32_t *t = saes_table[0];

    uint32_t x0 = ((uint32_t *)s)[0];
    uint32_t x1 = ((uint32_t *)s)[1];
    uint32_t x2 = ((uint32_t *)s)[2];
    uint32_t x3 = ((uint32_t *)s)[3];

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

    ((uint32_t *)s)[0] = y0 ^ ((uint32_t *)rk)[0];
    ((uint32_t *)s)[1] = y1 ^ ((uint32_t *)rk)[1];
    ((uint32_t *)s)[2] = y2 ^ ((uint32_t *)rk)[2];
    ((uint32_t *)s)[3] = y3 ^ ((uint32_t *)rk)[3];
}

/*──────────────────────────────────────────────────────────────────*/
/*  byte-shuffle helpers                                            */
/*──────────────────────────────────────────────────────────────────*/
static void unpacklo32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    memcpy(tmp, a, 4);           memcpy(tmp+4,  b, 4);
    memcpy(tmp+8, a+4, 4);       memcpy(tmp+12, b+4, 4);
    memcpy(t, tmp, 16);
}
static void unpackhi32(unsigned char *t, unsigned char *a, unsigned char *b)
{
    unsigned char tmp[16];
    memcpy(tmp, a+8, 4);         memcpy(tmp+4,  b+8, 4);
    memcpy(tmp+8, a+12,4);       memcpy(tmp+12, b+12,4);
    memcpy(t, tmp, 16);
}

/*──────────────────────────────────────────────────────────────────*/
/*  round-constants                                                 */
/*──────────────────────────────────────────────────────────────────*/
#include "haraka_constants.c"          /* → haraka_rc[40][16] */

static unsigned char rc[40][16];
static unsigned char rc_sseed[40][16];

/* copy reference RC once – for host unit-tests we use a constructor,
 * for SBF we use a manually placed startup stub (constructors ignored). */
static void init_rc(void) { memcpy(rc, haraka_rc, 40*16); }

#ifndef __BPF__
__attribute__((constructor))
static void init_rc_host(void) { init_rc(); }
#endif

__attribute__((section(".text.startup")))
static int _init(void) { init_rc(); return 0; }

/*──────────────────────────────────────────────────────────────────*/
/*  tweak_constants (VerusHash key-tweak)                            */
/*──────────────────────────────────────────────────────────────────*/
void tweak_constants(const unsigned char *pk_seed,
                     const unsigned char *sk_seed,
                     unsigned long long   seed_len)
{
    static unsigned char buf[40*16];       /* static – no stack */

    memcpy(rc, haraka_rc, 40*16);

    if (sk_seed) {
        haraka_S(buf, 40*16, sk_seed, seed_len);
        memcpy(rc_sseed, buf, 40*16);
    }
    haraka_S(buf, 40*16, pk_seed, seed_len);
    memcpy(rc, buf, 40*16);
}

/*──────────────────────────────────────────────────────────────────*/
/*  Haraka sponge (haraka_S)                                         */
/*──────────────────────────────────────────────────────────────────*/
#define HARAKAS_RATE 32
static void haraka512_perm(unsigned char *o,const unsigned char *i); /* fwd */

static void haraka_S_absorb(unsigned char *s,unsigned r,
                            const unsigned char *m,unsigned long long mlen,
                            unsigned char pad)
{
    unsigned char tmp[HARAKAS_RATE];

    while (mlen >= r) {
        for (unsigned j=0;j<r;++j) s[j]^=m[j];
        haraka512_perm(s,s);
        m   += r;
        mlen-= r;
    }
    memset(tmp,0,sizeof tmp);
    memcpy(tmp,m,mlen); tmp[mlen]=pad; tmp[r-1]|=0x80;
    for (unsigned j=0;j<r;++j) s[j]^=tmp[j];
}

static void haraka_S_squeeze(unsigned char *h,unsigned n,
                             unsigned char *s,unsigned r)
{
    while (n--) { haraka512_perm(s,s); memcpy(h,s,r); h+=r; }
}

void haraka_S(unsigned char *out,unsigned long long outlen,
              const unsigned char *in,unsigned long long inlen)
{
    unsigned char state[64]={0}, tmp[32];

    haraka_S_absorb(state,HARAKAS_RATE,in,inlen,0x1F);
    haraka_S_squeeze(out,outlen/32,state,HARAKAS_RATE);
    out += (outlen/32)*32;

    if (outlen & 31) {
        haraka_S_squeeze(tmp,1,state,HARAKAS_RATE);
        memcpy(out,tmp,outlen&31);
    }
}

/*──────────────────────────────────────────────────────────────────*/
/*  global scratch                                                  */
/*──────────────────────────────────────────────────────────────────*/
static unsigned char scratch512[64];
static unsigned char scratch256[32];
static unsigned char scratch16 [16];

/*──────────────────────────────────────────────────────────────────*/
/*  Haraka-512 permutation                                          */
/*──────────────────────────────────────────────────────────────────*/
static void haraka512_perm(unsigned char *out,const unsigned char *in)
{
    unsigned char *s=scratch512,*tmp=scratch16;

    memcpy(s,in,16);           memcpy(s+16,in+16,16);
    memcpy(s+32,in+32,16);     memcpy(s+48,in+48,16);

    for (unsigned r=0;r<5;++r) {
        for (unsigned j=0;j<2;++j) {
            aesenc(s     , rc[4*r*2+4*j  ]);
            aesenc(s+16  , rc[4*r*2+4*j+1]);
            aesenc(s+32  , rc[4*r*2+4*j+2]);
            aesenc(s+48  , rc[4*r*2+4*j+3]);
        }
        unpacklo32(tmp ,s   ,s+16);
        unpackhi32(s   ,s   ,s+16);
        unpacklo32(s+16,s+32,s+48);
        unpackhi32(s+32,s+32,s+48);
        unpacklo32(s+48,s   ,s+32);
        unpackhi32(s   ,s   ,s+32);
        unpackhi32(s+32,s+16,tmp );
        unpacklo32(s+16,s+16,tmp );
    }
    memcpy(out,s,64);
}

/* feed-forward + truncation */
void haraka512_port(unsigned char *out,const unsigned char *in)
{
    unsigned char *buf=scratch512;
    haraka512_perm(buf,in);
    for (unsigned i=0;i<64;++i) buf[i]^=in[i];

    memcpy(out    ,buf+ 8,8);
    memcpy(out+ 8 ,buf+24,8);
    memcpy(out+16 ,buf+32,8);
    memcpy(out+24 ,buf+48,8);
}

/*──────────────────────────────────────────────────────────────────*/
/*  Haraka-256                                                      */
/*──────────────────────────────────────────────────────────────────*/
void haraka256_port(unsigned char *out,const unsigned char *in)
{
    unsigned char *s=scratch256,*tmp=scratch16;

    memcpy(s,in,16); memcpy(s+16,in+16,16);

    for (unsigned r=0;r<5;++r) {
        for (unsigned j=0;j<2;++j) {
            aesenc(s    , rc[2*r*2+2*j  ]);
            aesenc(s+16 , rc[2*r*2+2*j+1]);
        }
        unpacklo32(tmp,s,s+16);
        unpackhi32(s+16,s,s+16);
        memcpy(s,tmp,16);
    }
    for (unsigned i=0;i<32;++i) out[i]=in[i]^s[i];
}

/* eof */
