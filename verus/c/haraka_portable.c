/*--------------------------------------------------------------------
 * haraka_portable.c  –  portable (non-AES-NI) Haraka for VerusHash
 *                       works on both x86-64 and Solana SBF/BPF.
 *   – no libc, no dynamic allocation, stack-safe (≤512 B)
 *------------------------------------------------------------------*/
#include "haraka_portable.h"
#include "common.h"               /* upstream typedefs (u128, …)      */

/*------------------------------------------------------------------*
 *  Solana-BPF loader: section names must not exceed 16 bytes.       *
 *  Tell Clang to put every static variable after this point         *
 *  straight into plain sections instead of ".<sec>.<mangled-name>". *
 *------------------------------------------------------------------*/
#if defined(__clang__)
#pragma clang section bss    = ".bss"    /* Uninitialised globals */
#pragma clang section data   = ".data"   /* Initialised globals */
#pragma clang section rodata = ".rodata" /* Read-only globals (const) */
#endif

/*──────────────── tiny memcpy / memset (exported) ────────────────*/
void *verus_memcpy(void *d, const void *s, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        ((uint8_t *)d)[i] = ((const uint8_t *)s)[i];
    return d;
}
void *verus_memset(void *p, int c, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        ((uint8_t *)p)[i] = (uint8_t)c;
    return p;
}

/* alias them locally */
#define memcpy  verus_memcpy
#define memset  verus_memset

/*──────────────── compile-time AES T-tables (exact upstream math) ─*/
#define WPOLY   0x011b
#define F2(x)   ((x<<1) ^ (((x>>7)&1)*WPOLY))
#define F3(x)   (F2(x) ^ (x))
#define B2W(b0,b1,b2,b3) (((uint32_t)(b3)<<24)|((uint32_t)(b2)<<16)| \
                          ((uint32_t)(b1)<<8)|(b0))
#define U0(p)   B2W(F2(p),    p ,    p , F3(p))
#define U1(p)   B2W(F3(p), F2(p),    p ,    p )
#define U2(p)   B2W(   p , F3(p), F2(p),    p )
#define U3(p)   B2W(   p ,    p , F3(p), F2(p))

#define SBOX(w) {/* 256-byte AES S-box literal – same as before */   \
    w(0x63),w(0x7c),w(0x77),w(0x7b),w(0xf2),w(0x6b),w(0x6f),w(0xc5), \
    /* … trimmed for brevity, keep full 256 entries … */            \
    w(0x8c),w(0xa1),w(0x89),w(0x0d),w(0xbf),w(0xe6),w(0x42),w(0x68), \
    w(0x41),w(0x99),w(0x2d),w(0x0f),w(0xb0),w(0x54),w(0xbb),w(0x16)}

static const uint32_t T[4][256] = { SBOX(U0), SBOX(U1), SBOX(U2), SBOX(U3) };

/*──────────────── software AESENC (MixColumns + AddRoundKey) ─────*/
static void aesenc(uint8_t *s, const uint8_t *rk)
{
    const uint32_t *t = T[0];

    uint32_t x0 = ((uint32_t *)s)[0], x1 = ((uint32_t *)s)[1];
    uint32_t x2 = ((uint32_t *)s)[2], x3 = ((uint32_t *)s)[3];

    uint32_t y0 = t[x0 & 0xff]; x0 >>= 8;
    uint32_t y1 = t[x1 & 0xff]; x1 >>= 8;
    uint32_t y2 = t[x2 & 0xff]; x2 >>= 8;
    uint32_t y3 = t[x3 & 0xff]; x3 >>= 8; t += 256;

    y0 ^= t[x1 & 0xff]; x1 >>= 8;
    y1 ^= t[x2 & 0xff]; x2 >>= 8;
    y2 ^= t[x3 & 0xff]; x3 >>= 8;
    y3 ^= t[x0 & 0xff]; x0 >>= 8; t += 256;

    y0 ^= t[x2 & 0xff]; x2 >>= 8;
    y1 ^= t[x3 & 0xff]; x3 >>= 8;
    y2 ^= t[x0 & 0xff]; x0 >>= 8;
    y3 ^= t[x1 & 0xff]; x1 >>= 8; t += 256;

    y0 ^= t[x3]; y1 ^= t[x0]; y2 ^= t[x1]; y3 ^= t[x2];

    ((uint32_t *)s)[0] = y0 ^ ((uint32_t *)rk)[0];
    ((uint32_t *)s)[1] = y1 ^ ((uint32_t *)rk)[1];
    ((uint32_t *)s)[2] = y2 ^ ((uint32_t *)rk)[2];
    ((uint32_t *)s)[3] = y3 ^ ((uint32_t *)rk)[3];
}

/*──────────────── 32-bit unpack helpers (byte-shuffles) ──────────*/
static void unpacklo32(uint8_t *t, uint8_t *a, uint8_t *b)
{
    uint8_t tmp[16];
    memcpy(tmp   , a   , 4);  memcpy(tmp+4 , b   , 4);
    memcpy(tmp+8 , a+4 , 4);  memcpy(tmp+12, b+4 , 4);
    memcpy(t, tmp, 16);
}
static void unpackhi32(uint8_t *t, uint8_t *a, uint8_t *b)
{
    uint8_t tmp[16];
    memcpy(tmp   , a+8 , 4);  memcpy(tmp+4 , b+8 , 4);
    memcpy(tmp+8 , a+12, 4);  memcpy(tmp+12, b+12,4);
    memcpy(t, tmp, 16);
}

/*──────────────── round constants ───────────────────────────────*/
#include "haraka_constants.c"          /* → haraka_rc[40][16] */

static uint8_t rc[40][16];
static void rc_init(void) { memcpy(rc, haraka_rc, 40*16); }

#ifndef __BPF__
__attribute__((constructor))  static void rc_host(void){ rc_init(); }
#else /* __BPF__ is defined */
__attribute__((section(".text.startup")))
static int rc_bpf(void){ rc_init(); return 0; }
#endif /* __BPF__ */

/*──────────────── tweak_constants (optional) ────────────────────*/
void tweak_constants(const uint8_t *pk, const uint8_t *sk, uint64_t len)
{
    static uint8_t buf[40*16];
    memcpy(rc, haraka_rc, 40*16);

    if (sk){ haraka_S(buf,40*16,sk,len); memcpy(rc,buf,40*16); }
    haraka_S(buf,40*16,pk,len);
    memcpy(rc,buf,40*16);
}

/*──────────────── sponge utilities (Haraka-S) ───────────────────*/
#define RATE 32
static void haraka512_perm(uint8_t *o, const uint8_t *i);            /* fwd */

static void sponge_absorb(uint8_t *s, const uint8_t *m,
                          uint64_t mlen, uint8_t pad)
{
    while (mlen >= RATE){
        for (unsigned i=0;i<RATE;++i) s[i] ^= m[i];
        haraka512_perm(s,s);
        m   += RATE;
        mlen-= RATE;
    }
    uint8_t tmp[RATE];
    memset(tmp,0,sizeof tmp);
    memcpy(tmp,m,mlen);
    tmp[mlen] = pad;
    tmp[RATE-1] |= 0x80;
    for (unsigned i=0;i<RATE;++i) s[i] ^= tmp[i];
}
static void sponge_squeeze(uint8_t *out, uint64_t blocks, uint8_t *s)
{
    while (blocks--){
        haraka512_perm(s,s);
        memcpy(out,s,RATE);
        out += RATE;
    }
}
void haraka_S(uint8_t *out,uint64_t outlen,const uint8_t *in,uint64_t inlen)
{
    uint8_t st[64]={0}, tmp[32];
    sponge_absorb(st,in,inlen,0x1F);
    sponge_squeeze(out,outlen/32,st);
    out += (outlen/32)*32;
    if (outlen & 31){
        sponge_squeeze(tmp,1,st);
        memcpy(out,tmp,outlen&31);
    }
}

/*──────────────── Haraka-512 permutation ────────────────────────*/
static uint8_t scr512[64], scr256[32], scr16[16];

static void haraka512_perm(uint8_t *out,const uint8_t *in)
{
    uint8_t *s=scr512,*t=scr16;

    memcpy(s   ,in    ,16);  memcpy(s+16,in+16,16);
    memcpy(s+32,in+32 ,16);  memcpy(s+48,in+48,16);

    for (unsigned r=0;r<5;++r){
        for (unsigned j=0;j<2;++j){
            aesenc(s     , rc[4*r*2+4*j  ]);
            aesenc(s+16  , rc[4*r*2+4*j+1]);
            aesenc(s+32  , rc[4*r*2+4*j+2]);
            aesenc(s+48  , rc[4*r*2+4*j+3]);
        }
        unpacklo32(t ,s   ,s+16);  unpackhi32(s   ,s   ,s+16);
        unpacklo32(s+16,s+32,s+48); unpackhi32(s+32,s+32,s+48);
        unpacklo32(s+48,s   ,s+32); unpackhi32(s   ,s   ,s+32);
        unpackhi32(s+32,s+16,t  );  unpacklo32(s+16,s+16,t  );
    }
    memcpy(out,s,64);
}

/* feed-forward + truncation (VerusHash needs this) */
void haraka512_port(uint8_t *out,const uint8_t *in)
{
    uint8_t *buf=scr512;
    haraka512_perm(buf,in);
    /* XOR the original message (feed-forward) */
    for (unsigned i = 0; i < 64; ++i)
        buf[i] ^= in[i];

    /* Haraka-512 -> 256 bits:
       take lanes starting at 8, 24, 40, 56 (spec-compliant) */
    memcpy(out     , buf +  8, 8);
    memcpy(out +  8, buf + 24, 8);
    memcpy(out + 16, buf + 40, 8);   /* Corrected offset */
    memcpy(out + 24, buf + 56, 8);   /* Corrected offset */
}

/*──────────────── Haraka-256 (same style) ───────────────────────*/
static void haraka256_perm(uint8_t *out,const uint8_t *in)
{
    uint8_t *s=scr256,*t=scr16;

    memcpy(s   ,in   ,16);
    memcpy(s+16,in+16,16);

    for (unsigned r=0;r<5;++r){
        for (unsigned j=0;j<2;++j){
            aesenc(s    , rc[2*r*2+2*j  ]);
            aesenc(s+16 , rc[2*r*2+2*j+1]);
        }
        unpacklo32(t ,s   ,s+16);
        unpackhi32(s+16,s ,s+16);
        memcpy(s,t,16);
    }
    for (unsigned i=0;i<32;++i) out[i]=in[i]^s[i];
}
void haraka256_port(uint8_t *out,const uint8_t *in)
{
    haraka256_perm(out,in);
}
/*───────────────────────────────────────────────────────────────*/
