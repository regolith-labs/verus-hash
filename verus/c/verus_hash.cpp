#include <stdint.h>
#include "verus_hash.h"
#include "haraka_portable.h"
#include "uint256.h"
#include "common.h"

/* ---- simple portable implementation: 80-byte header only ---- */

void verus_hash_v2(unsigned char *out, const unsigned char *in, unsigned int len)
{
    /* VerusHash 2.0 spec: Haraka-256( header ‖ header ) → LE */
    unsigned char buf[64] = {0};
    if (len > 80) len = 80;          /* safety */
    for (unsigned i=0;i<len;i++) buf[i] = in[i];
    for (unsigned i=0;i<len;i++) buf[i+32] = in[i];  /* repeat */

    unsigned char tmp[32];
    haraka256_port(tmp, buf);

    /* little-endian output expected by upstream code */
    for (int i=0;i<32;i++) out[i] = tmp[31 - i];
}

/* ------- global init, called once from Rust ---------- */
// Renamed from init_verus_hash to match Rust FFI declaration.
// Removed __attribute__((constructor)) as Rust calls this explicitly.
// Made non-static so it's visible externally.
void verus_hash_v2_init()
{
    // Initialize constants using the primary seed "VRSC" and no secondary seed.
    tweak_constants((const unsigned char*)"VRSC", nullptr, 4);
}
