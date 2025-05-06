#include <stdint.h>
#include "verus_hash.h"
#include "haraka_portable.h" // Includes verus_memcpy/verus_memset declarations
#include "uint256.h"
#include "common.h" // Includes stddef.h for size_t
#include "verus_clhash.h" // Include CLHASH definitions for v2.2

/*------------------------------------------------------------------*
 *  Solana-BPF loader: section names must not exceed 16 bytes.       *
 *  Tell Clang to put every static variable after this point         *
 *  straight into plain sections instead of ".<sec>.<mangled-name>". *
 *------------------------------------------------------------------*/
#if defined(__clang__) && defined(__ELF__)
#  pragma clang section bss    = ".bss"    /* Uninitialised globals */
#  pragma clang section data   = ".data"   /* Initialised globals */
#  pragma clang section rodata = ".rodata" /* Read-only globals (const) */
#endif /* __clang__ && __ELF__ */

/* ---- Full VerusHash 1.0 Implementation ---- */
// Based on CVerusHash::Hash from origin-impl, using haraka512_port_zero

void verus_hash(unsigned char *result, const unsigned char *data, size_t len)
{
    unsigned char buf[128]; // Stack buffer for sponge state
    unsigned char *bufPtr = buf;
    int nextOffset = 64;
    size_t pos = 0;
    unsigned char *bufPtr2 = bufPtr + nextOffset;
    const unsigned char *ptr = data;

    // Initialize the first 32 bytes of the buffer (initial state) to zero
    verus_memset(bufPtr, 0, 32);

    // Digest up to 32 bytes at a time
    for ( ; pos < len; pos += 32)
    {
        // Copy next 32 bytes (or less with padding) into the second half of the current buffer
        if (len - pos >= 32)
        {
            verus_memcpy(bufPtr + 32, ptr + pos, 32);
        }
        else
        {
            size_t i = len - pos;
            verus_memcpy(bufPtr + 32, ptr + pos, i);
            // Zero-pad the remaining bytes in the second half
            verus_memset(bufPtr + 32 + i, 0, 32 - i);
        }
        // Apply the Haraka-512 permutation with zero constants
        haraka512_port_zero(bufPtr2, bufPtr);

        // Swap buffer pointers for the next round
        bufPtr2 = bufPtr;
        bufPtr += nextOffset;
        nextOffset *= -1;
    }
    // The final 32-byte hash is in the buffer pointed to by bufPtr
    verus_memcpy(result, bufPtr, 32);
}


/* ---- Full VerusHash 2.2 Implementation ---- */

void verus_hash_v2(unsigned char *out, const unsigned char *in, size_t len)
{
    /* ------------- Sponge over Haraka-512 ------------- */
    uint8_t S[64] = {0}, tmp[64]; // Initialize state S to zeros
    size_t i = 0;
    while (i + 32 <= len) {                    /* absorb full 32-byte blocks */
        for (int j=0;j<32;++j) S[j] ^= in[i+j]; // XOR input block into the first 32 bytes of state
        haraka512_port(tmp, S);                // Apply Haraka-512 permutation to state S -> tmp
        // The reference code seems to use a simple permutation update, not XOR feed-forward here.
        // Let's follow the provided code block exactly for the sponge part.
        // Original provided code: for (int j=0;j<64;++j) S[j] ^= tmp[j]; /* feed-forward */
        // Let's stick to the provided code block:
        // Restore the original feed-forward XOR step to match reference implementation
        for (int j=0;j<64;++j) S[j] ^= tmp[j]; // XOR feed-forward
        i += 32;
    }

    /* absorb last partial block + 10* padding */
    // XOR in remaining bytes
    size_t remaining = len - i;
    for(size_t j=0; j<remaining; ++j) {
        S[j] ^= in[i+j]; // XOR into the start of the state buffer
    }
    // Apply padding: XOR 0x01 at the position after the last byte
    S[remaining] ^= 0x01;
    // XOR 0x80 into the last byte of the 64-byte state
    S[63] ^= 0x80;

    // Final permutation after padding
    haraka512_port(tmp, S);
    // Update state S with the final permuted output
    for (int j=0;j<64;++j) S[j] = tmp[j];


    /* ------------- CLHASH mix (first 64 bytes of input) ------------- */
    // uint64_t *s64 = (uint64_t*)S; // Removed: No longer used, access via verus_memcpy
    uint64_t k1 = CLHASH_K1, k2 = CLHASH_K2;
    uint64_t mix = 0;
    uint8_t block[64]; // Buffer for the first 64 bytes of input (or less, padded)
    verus_memset(block, 0, 64); // Zero initialize block for padding
    size_t cpy = len < 64 ? len : 64;
    verus_memcpy(block, in, cpy); // Copy up to 64 bytes from original input

    // Mix each 64-bit lane of the input block with the corresponding state lane
    for (int lane=0; lane<8; ++lane) {
        uint64_t m; // Input lane
        // Safely read 8 bytes from block into m
        verus_memcpy(&m, &block[lane * 8], sizeof(uint64_t));

        uint64_t s_lane; // State lane
        // Safely read 8 bytes from S (state) into s_lane
        verus_memcpy(&s_lane, &S[lane * 8], sizeof(uint64_t));

        uint64_t p = (lane&1) ? k2 : k1;       // Select CLHASH key based on lane
        // clmul_mix(key ^ state_lane, input_lane)
        mix ^= clmul_mix(p ^ s_lane, m);
    }
    // XOR the final mix value back into each lane of the state
    for (int lane=0; lane<8; ++lane) {
        uint64_t s_lane;
        // Safely read 8 bytes from S into s_lane
        verus_memcpy(&s_lane, &S[lane * 8], sizeof(uint64_t));
        s_lane ^= mix; // Apply the mix to the local variable
        // Safely write the modified 8 bytes back to S
        verus_memcpy(&S[lane * 8], &s_lane, sizeof(uint64_t));
    }

    /* ------------- Final Haraka-256 ------------- */
    uint8_t F[32]; // Buffer for final hash output
    // Hash the first 32 bytes of the mixed state S using Haraka-256
    // Note: Haraka-256 takes the first 32 bytes of S as input.
    haraka256_port(F, S);              /* BE output */

    // Convert final hash F (Big-Endian) to Little-Endian for output `out`
    for (int j=0;j<32;++j) out[j] = F[31-j];   /* LE */
}

/* Initialization function is no longer needed. */
/* Constants are baked in via haraka_rc_vrsc.inc at compile time. */
