// (C) 2018 The Verus Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
This provides the PoW hash function for Verus, a CPU-optimized hash 
function with a Haraka V2 core. Unlike Haraka, which is made for short 
inputs only, Verus Hash takes any length of input and produces a 256 
bit output.
*/
// #include <string.h> // For memset, memcpy. Will be replaced by BPF equivalents or compiler builtins. // Removed for SBF
#include "common.h"
#include "verus_hash.h"
#include "haraka_portable.h" // For verus_memcpy, verus_memset

extern "C" {
#include "haraka.h"
// haraka_portable.h already included above
}

void (*CVerusHash::haraka512Function)(unsigned char *out, const unsigned char *in);

void CVerusHash::Hash(void *result, const void *data, size_t _len)
{
    alignas(32) unsigned char buf[128]; // Ensure alignment for Haraka
    unsigned char *bufPtr = buf;
    int nextOffset = 64;
    uint32_t pos = 0, len = _len;
    unsigned char *bufPtr2 = bufPtr + nextOffset;
    unsigned char *ptr = (unsigned char *)data;

    // put our last result or zero at beginning of buffer each time
    verus_memset(bufPtr, 0, 32);

    // digest up to 32 bytes at a time
    for ( ; pos < len; pos += 32)
    {
        if (len - pos >= 32)
        {
            verus_memcpy(bufPtr + 32, ptr + pos, 32);
        }
        else
        {
            int i = (int)(len - pos);
            verus_memcpy(bufPtr + 32, ptr + pos, i);
            verus_memset(bufPtr + 32 + i, 0, 32 - i);
        }
        (*haraka512Function)(bufPtr2, bufPtr);
        bufPtr2 = bufPtr;
        bufPtr += nextOffset;
        nextOffset *= -1;
    }
    verus_memcpy(result, bufPtr, 32);
};

void CVerusHash::init()
{
#ifdef VERUS_BPF_TARGET
    haraka512Function = &haraka512_port_zero;
#else
    if (IsCPUVerusOptimized())
    {
        haraka512Function = &haraka512_zero;
    }
    else
    {
        haraka512Function = &haraka512_port_zero;
    }
#endif // VERUS_BPF_TARGET
}

CVerusHash &CVerusHash::Write(const unsigned char *data, size_t _len)
{
    unsigned char *tmp;
    uint32_t pos, len = _len;

    // digest up to 32 bytes at a time
    for ( pos = 0; pos < len; )
    {
        uint32_t room = 32 - curPos;

        if (len - pos >= room)
        {
            verus_memcpy(curBuf + 32 + curPos, data + pos, room);
            (*haraka512Function)(result, curBuf);
            tmp = curBuf;
            curBuf = result;
            result = tmp;
            pos += room;
            curPos = 0;
        }
        else
        {
            verus_memcpy(curBuf + 32 + curPos, data + pos, len - pos);
            curPos += len - pos;
            pos = len;
        }
    }
    return *this;
}

// to be declared and accessed from C
void verus_hash(void *result, const void *data, size_t len)
{
    return CVerusHash::Hash(result, data, len);
}

void (*CVerusHashV2::haraka512Function)(unsigned char *out, const unsigned char *in);
void (*CVerusHashV2::haraka512KeyedFunction)(unsigned char *out, const unsigned char *in, const u128 *rc);
void (*CVerusHashV2::haraka256Function)(unsigned char *out, const unsigned char *in);

void CVerusHashV2::init()
{
#ifdef VERUS_BPF_TARGET
    // For BPF, always use portable versions and ensure constants are loaded.
    load_constants_port(); // From haraka_portable.h
    haraka512Function = &haraka512_port;
    haraka512KeyedFunction = &haraka512_port_keyed; // Not used by Finalize() but set for completeness
    haraka256Function = &haraka256_port;         // Not used by Finalize() but set for completeness
#else
    if (IsCPUVerusOptimized())
    {
        load_constants(); // From haraka.h
        haraka512Function = &haraka512;
        haraka512KeyedFunction = &haraka512_keyed;
        haraka256Function = &haraka256;
    }
    else
    {
        // load the haraka constants
        load_constants_port(); // From haraka_portable.h
        haraka512Function = &haraka512_port;
        haraka512KeyedFunction = &haraka512_port_keyed;
        haraka256Function = &haraka256_port;
    }
#endif // VERUS_BPF_TARGET
}

void CVerusHashV2::Hash(void *result, const void *data, size_t len)
{
    alignas(32) unsigned char buf[128]; // Ensure alignment for Haraka
    unsigned char *bufPtr = buf;
    int pos = 0, nextOffset = 64;
    unsigned char *bufPtr2 = bufPtr + nextOffset;
    unsigned char *ptr = (unsigned char *)data;

    // put our last result or zero at beginning of buffer each time
    verus_memset(bufPtr, 0, 32);

    // digest up to 32 bytes at a time
    for ( ; pos < (int)len; pos += 32) // Cast len to int for comparison with pos
    {
        if ((int)len - pos >= 32) // Cast len to int
        {
            verus_memcpy(bufPtr + 32, ptr + pos, 32);
        }
        else
        {
            int i = (int)(len - pos); // Cast len to int
            verus_memcpy(bufPtr + 32, ptr + pos, i);
            verus_memset(bufPtr + 32 + i, 0, 32 - i);
        }
        (*haraka512Function)(bufPtr2, bufPtr);
        bufPtr2 = bufPtr;
        bufPtr += nextOffset;
        nextOffset *= -1;
    }
    verus_memcpy(result, bufPtr, 32);
};

CVerusHashV2 &CVerusHashV2::Write(const unsigned char *data, size_t len)
{
    unsigned char *tmp;

    // digest up to 32 bytes at a time
    for (int pos = 0; pos < (int)len; ) // Cast len to int
    {
        int room = 32 - curPos;

        if ((int)len - pos >= room) // Cast len to int
        {
            verus_memcpy(curBuf + 32 + curPos, data + pos, room);
            (*haraka512Function)(result, curBuf);
            tmp = curBuf;
            curBuf = result;
            result = tmp;
            pos += room;
            curPos = 0;
        }
        else
        {
            verus_memcpy(curBuf + 32 + curPos, data + pos, (int)len - pos); // Cast len to int
            curPos += (int)len - pos; // Cast len to int
            pos = (int)len; // Cast len to int
        }
    }
    return *this;
}

// FFI function for VerusHashV2 (Finalize path)
// Global/static initializer for CVerusHashV2
static bool verus_hash_v2_initialized = false;

extern "C" void verus_hash_v2_c(
    unsigned char *output,
    const unsigned char *input,
    size_t input_len)
{
    if (!verus_hash_v2_initialized) {
        CVerusHashV2::init();
        verus_hash_v2_initialized = true;
    }

#ifdef VERUS_BPF_TARGET
    CVerusHashV2 hasher; // solutionVersion parameter is unused in BPF constructor path
#else
    // For non-BPF, pass the default solution version.
    // This path might still try to use thread_local stuff if not careful,
    // but for BPF target, the constructor is simplified.
    CVerusHashV2 hasher(SOLUTION_VERUSHHASH_V2);
#endif
    hasher.Write(input, input_len);
    hasher.Finalize(output);
}

// Original C-style verus_hash_v2, now calls the static method of CVerusHashV2
void verus_hash_v2(void *result, const void *data, size_t len)
{
    if (!verus_hash_v2_initialized) {
        CVerusHashV2::init();
        verus_hash_v2_initialized = true;
    }
    return CVerusHashV2::Hash(result, data, len);
}
