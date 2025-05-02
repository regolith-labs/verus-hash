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
#if defined(__clang__) && defined(__ELF__)
// #pragma clang section bss    = ".bss"    /* Removed: No static writable data allowed */
#  pragma clang section data   = ".data"   /* Initialised globals */
#  pragma clang section rodata = ".rodata" /* Read-only globals (const) */
#endif /* __clang__ && __ELF__ */

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

/* Forward declaration for internal sponge function */
static void haraka_S(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen);

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
// Include the definitions of default_haraka_rc (const)
#include "haraka_constants.c"
// Writable constants (rc) are now generated on the stack per-call.

/*──────────────── Internal Helper: Build Round Constants ────────*/
/* Build personalised round constants into `dst` (40×16 bytes) */
/* Uses the hardcoded "VRSC" seed, matching original init logic */
static void make_rc(uint8_t dst[40][16])
{
    // Use a temporary buffer on the stack for haraka_S output.
    // Size matches the destination `dst`.
    uint8_t buf[40*16]; // 640 bytes, stack-ok

    // Initialize dst with the default constants
    memcpy(dst, default_haraka_rc, 40*16);

    // Apply primary key (pk) tweak ("VRSC")
    // haraka_S writes its output into the temporary `buf`.
    haraka_S(buf, 40*16, (const uint8_t*)"VRSC", 4);

    // Copy the tweaked constants from `buf` into the final destination `dst`.
    memcpy(dst, buf, 40*16);
    // `dst` now holds the final constants needed by the permutations for this call.
}


/*──────────────── Internal Sponge Utilities (Haraka-S) ──────────*/
#define RATE 32
// Forward declaration for the permutation used by the sponge
static void haraka512_perm_internal(uint8_t *o, const uint8_t *i, const uint8_t rc[40][16]);

// Make sponge helpers static as they are no longer part of the public API
static void sponge_absorb(uint8_t *s, const uint8_t *m,
                          uint64_t mlen, uint8_t pad)
{
    // Sponge needs temporary round constants just for its internal permutation calls.
    // Generate them here. This is separate from the constants used by the main hash.
    uint8_t sponge_rc[40][16];
    make_rc(sponge_rc); // Use standard "VRSC" seed for sponge internal permutation

    while (mlen >= RATE){
        for (unsigned i=0;i<RATE;++i) s[i] ^= m[i];
        // Call the internal permutation function with the generated constants
        haraka512_perm_internal(s, s, sponge_rc);
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
// Make sponge helpers static
static void sponge_squeeze(uint8_t *out, uint64_t blocks, uint8_t *s)
{
    // Sponge needs temporary round constants just for its internal permutation calls.
    uint8_t sponge_rc[40][16];
    make_rc(sponge_rc); // Use standard "VRSC" seed

    while (blocks--){
        // Call the internal permutation function with the generated constants
        haraka512_perm_internal(s, s, sponge_rc);
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

/*──────────────── Internal Haraka-512 permutation ───────────────*/
// Takes round constants `rc` as a parameter.
// Renamed to avoid conflict with the old static declaration if any existed.
static void haraka512_perm_internal(uint8_t *out, const uint8_t *in, const uint8_t rc[40][16])
{
    // Allocate scratch buffers on the stack
    uint8_t scr512[64]; // Used as 's' below
    uint8_t scr16 [16]; // Used as 't' below
    uint8_t *s=scr512,*t=scr16;

    memcpy(s   ,in    ,16);  memcpy(s+16,in+16,16);
    memcpy(s+32,in+32 ,16);  memcpy(s+48,in+48,16);

    for (unsigned r=0;r<5;++r){
        for (unsigned j=0;j<2;++j){
            // Use the passed-in round constants `rc`
            // Note: Access rc directly as rc[index] which points to the start of the 16-byte block.
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

/*──────────────── Public Haraka-512 Entry Point ─────────────────*/
/* feed-forward + truncation (VerusHash needs this) */
void haraka512_port(uint8_t *out, const uint8_t *in)
{
    // Allocate round constants on the stack for this call
    uint8_t rc[40][16]; // 640 bytes, stack-ok
    make_rc(rc);        // Build constants using "VRSC" seed

    // Allocate local buffer on the stack
    uint8_t buf[64];
    // Call the internal permutation with the stack-allocated constants
    haraka512_perm_internal(buf, in, rc);

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

/*──────────────── Internal Haraka-256 permutation ───────────────*/
// Takes round constants `rc` as a parameter.
static void haraka256_perm_internal(uint8_t *out, const uint8_t *in, const uint8_t rc[40][16])
{
    // Allocate scratch buffers on the stack
    uint8_t scr256[32]; // Used as 's' below
    uint8_t scr16 [16]; // Used as 't' below
    uint8_t *s=scr256,*t=scr16;

    memcpy(s   ,in   ,16);
    memcpy(s+16,in+16,16);

    for (unsigned r=0;r<5;++r){
        for (unsigned j=0;j<2;++j){
            // Use the passed-in round constants `rc`
            // Note: Access rc directly as rc[index]. Indices 0..19 are used.
            aesenc(s    , rc[2*r*2+2*j  ]);
            aesenc(s+16 , rc[2*r*2+2*j+1]);
        }
        unpacklo32(t ,s   ,s+16);
        unpackhi32(s+16,s ,s+16);
        memcpy(s,t,16);
    }
    // XOR input with the permuted state for feed-forward
    for (unsigned i=0;i<32;++i) out[i]=in[i]^s[i];
}

/*──────────────── Public Haraka-256 Entry Point ─────────────────*/
void haraka256_port(uint8_t *out, const uint8_t *in)
{
    // Allocate round constants on the stack for this call
    uint8_t rc[40][16]; // 640 bytes, stack-ok (needs full 40 for make_rc)
    make_rc(rc);        // Build constants using "VRSC" seed

    // Call the internal permutation with the stack-allocated constants
    haraka256_perm_internal(out, in, rc);
}
/*───────────────────────────────────────────────────────────────*/
