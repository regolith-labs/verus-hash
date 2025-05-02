#include <stdint.h>
#include "verus_hash.h"
#include "haraka_portable.h" // Includes verus_memcpy/verus_memset declarations
#include "uint256.h"
#include "common.h" // Includes stddef.h for size_t

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

/* ---- simple portable implementation: VerusHash 2.0 ---- */

void verus_hash_v2(unsigned char *out, const unsigned char *in, unsigned int len)
{
    /* VerusHash 2.0 spec: Haraka-256( first_32_bytes(in) ‖ first_32_bytes(in) ) → LE */
    unsigned char buf[64]; // No need to zero-init, we overwrite fully

    // Prepare the first 32 bytes, zero-padding if len < 32
    if (len >= 32) {
        // Use our custom memcpy
        verus_memcpy(buf, in, 32);
    } else {
        // Use our custom memcpy and memset
        verus_memcpy(buf, in, len);
        verus_memset(buf + len, 0, 32 - len); // Zero pad the rest
    }

    // Concatenate the first 32 bytes with itself using our custom memcpy
    verus_memcpy(buf + 32, buf, 32);

    // Hash the 64-byte buffer using Haraka-256
    unsigned char tmp[32];
    haraka256_port(tmp, buf);

    /* Convert Haraka output (BE) to the expected Little-Endian format */
    // The haraka*_port functions produce Big-Endian output.
    // The test vector `expected_verus_le` is Little-Endian.
    // So, we need to reverse the `tmp` buffer.
    for (int i=0; i<32; i++) {
        out[i] = tmp[31 - i];
    }
}

/* Initialization is no longer needed externally. */
/* Round constants are generated on the stack within haraka*_port calls. */
