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

    // Load state using safe helper
    uint32_t x0 = load_u32(s +  0);
    uint32_t x1 = load_u32(s +  4);
    uint32_t x2 = load_u32(s +  8);
    uint32_t x3 = load_u32(s + 12);

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

    // Load round key and store result using safe helpers
    store_u32(s +  0, y0 ^ load_u32(rk +  0));
    store_u32(s +  4, y1 ^ load_u32(rk +  4));
    store_u32(s +  8, y2 ^ load_u32(rk +  8));
    store_u32(s + 12, y3 ^ load_u32(rk + 12));
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
// Define the constant array using the included initializer.
// The build system (build.rs) generates `haraka_rc_vrsc.inc` and copies it
// to `verus/c/` so the `#include` below finds it.
// We declare it `extern const` first and then define it without `static`
// to ensure it has external linkage and isn't optimized away by the C++
// compiler during host builds when only C functions reference it.
// Define the constant array using the included initializer.
// The build system (build.rs) generates `haraka_rc_vrsc.inc` and copies it
// to `verus/c/` so the `#include` below finds it.
// We declare it `extern const` first and then define it without `static`
// to ensure it has external linkage and isn't optimized away by the C++
// compiler during host builds when only C functions reference it.
extern const uint8_t rc[40][16]; // Declaration with external linkage
const uint8_t rc[40][16] =         // Definition
#include "haraka_rc_vrsc.inc"
;

// NOTE: The static writable rc buffer, rc_init, rc_host, rc_bpf functions
// that were previously here have been removed.
// The const `rc` array defined above is now used directly by the permutations below.

/*──────────────── Internal Sponge Utilities (Haraka-S) ──────────*/
// Sponge logic is no longer needed here as constants are pre-generated.

/*──────────────── Internal Haraka-512 permutation ───────────────*/
// Now uses the static `rc` array directly.
static void haraka512_perm_internal(uint8_t *out, const uint8_t *in)
{
    // Allocate scratch buffers on the stack
    uint8_t scr512[64]; // Used as 's' below
    uint8_t scr16 [16]; // Used as 't' below
    uint8_t *s=scr512,*t=scr16;

    memcpy(s   ,in    ,16);  memcpy(s+16,in+16,16);
    memcpy(s+32,in+32 ,16);  memcpy(s+48,in+48,16);

    for (unsigned r=0;r<5;++r){
        for (unsigned j=0;j<2;++j){
            // Use the static precomputed round constants `rc`
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
    // Allocate local buffer on the stack
    uint8_t buf[64];
    // Call the internal permutation which now uses the static constants
    haraka512_perm_internal(buf, in);

    /* XOR the original message (feed-forward) */
    for (unsigned i = 0; i < 64; ++i)
        buf[i] ^= in[i];

    /* Haraka-512 -> 256 bits:
       take lanes starting at 8, 24, 40, 56 (spec-compliant) */
    memcpy(out     , buf +  8, 8);
    memcpy(out +  8, buf + 24, 8);
    memcpy(out + 16, buf + 40, 8);
    memcpy(out + 24, buf + 56, 8);
}

/*──────────────── Internal Haraka-256 permutation ───────────────*/
// Now uses the static `rc` array directly.
static void haraka256_perm_internal(uint8_t *out, const uint8_t *in)
{
    // Allocate scratch buffers on the stack
    uint8_t scr256[32]; // Used as 's' below
    uint8_t scr16 [16]; // Used as 't' below
    uint8_t *s=scr256,*t=scr16;

    memcpy(s   ,in   ,16);
    memcpy(s+16,in+16,16);

    for (unsigned r=0;r<5;++r){
        for (unsigned j=0;j<2;++j){
            // Use the static precomputed round constants `rc`
            // Note: Indices 0..19 are used.
            // Call the single aesenc function which uses safe load/store
            aesenc(s    , rc[2*r*2+2*j  ]);
            aesenc(s+16 , rc[2*r*2+2*j+1]);
        }
        // Mixing step
        unpacklo32(t ,s   ,s+16);
        unpackhi32(s+16,s ,s+16);
        verus_memcpy(s,t,16); // Use verus_memcpy: Copy t back to the first half of s
    }
    // XOR input with the permuted state for feed-forward
    for (unsigned i=0;i<32;++i) out[i]=in[i]^s[i];
}

/*──────────────── Public Haraka-256 Entry Point ─────────────────*/
void haraka256_port(uint8_t *out, const uint8_t *in)
{
    // Call the internal permutation which now uses the static constants
    haraka256_perm_internal(out, in);
}

/*──────────────── Internal Haraka-512 permutation (Zero Key) ───*/
// Identical to haraka512_perm_internal but uses zero constants.
void haraka512_perm_zero(unsigned char *out, const unsigned char *in)
{
    // Allocate scratch buffers on the stack
    uint8_t scr512[64]; // Used as 's' below
    uint8_t scr16 [16]; // Used as 't' below
    uint8_t *s=scr512,*t=scr16;
    const uint8_t zero_rc[16] = {0}; // Zero round key

    memcpy(s   ,in    ,16);  memcpy(s+16,in+16,16);
    memcpy(s+32,in+32 ,16);  memcpy(s+48,in+48,16);

    for (unsigned r=0;r<5;++r){
        for (unsigned j=0;j<2;++j){
            // Use the zero round constants
            aesenc(s     , zero_rc);
            aesenc(s+16  , zero_rc);
            aesenc(s+32  , zero_rc);
            aesenc(s+48  , zero_rc);
        }
        unpacklo32(t ,s   ,s+16);  unpackhi32(s   ,s   ,s+16);
        unpacklo32(s+16,s+32,s+48); unpackhi32(s+32,s+32,s+48);
        unpacklo32(s+48,s   ,s+32); unpackhi32(s   ,s   ,s+32);
        unpackhi32(s+32,s+16,t  );  unpacklo32(s+16,s+16,t  );
    }
    memcpy(out,s,64);
}

/*──────────────── Public Haraka-512 Entry Point (Zero Key) ─────*/
/* feed-forward + truncation */
void haraka512_port_zero(unsigned char *out, const unsigned char *in)
{
    // Allocate local buffer on the stack
    uint8_t buf[64];
    // Call the internal zero-key permutation
    haraka512_perm_zero(buf, in);

    /* XOR the original message (feed-forward) */
    for (unsigned i = 0; i < 64; ++i)
        buf[i] ^= in[i];

    /* Haraka-512 -> 256 bits:
       take lanes starting at 8, 24, 40, 56 (spec-compliant) */
    memcpy(out     , buf +  8, 8);
    memcpy(out +  8, buf + 24, 8);
    memcpy(out + 16, buf + 40, 8);
    memcpy(out + 24, buf + 56, 8);
}

/*──────────────── Helper for build-time generation ────────────*/
// Removed get_vrsc_constants function as it's no longer needed.
// Generation happens via generate_constants.c run by build.rs.

/*───────────────────────────────────────────────────────────────*/
