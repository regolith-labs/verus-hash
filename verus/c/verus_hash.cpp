#include <stdint.h>
#include "verus_hash.h"
#include "haraka_portable.h"
#include "uint256.h"
#include "common.h"

/* ---- simple portable implementation: 80-byte header only ---- */

void verus_hash_32(unsigned char *out, const unsigned char *in, unsigned int len)
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
__attribute__((constructor))
static void init_verus_hash()
{
    load_constants_port(nullptr, (const unsigned char*)"VRSC", 4);
}
