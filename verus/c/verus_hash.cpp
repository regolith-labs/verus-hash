// (C) 2023 The Verus Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
This provides the PoW hash function for Verus, a CPU-optimized hash 
function with a Haraka V2 core. Unlike Haraka, which is made for short 
inputs only, Verus Hash takes any length of input and produces a 256 
bit output.
*/
#include "common.h"      // Updated include path
#include "verus_hash.h"  // Updated include path

// Define static members at file scope
// CVerusHash is deprecated/unused for V2+, remove its static member
// void (*CVerusHash::haraka512Function)(unsigned char *out, const unsigned char *in);
void (*CVerusHashV2::haraka512Function)(unsigned char *out, const unsigned char *in);
void (*CVerusHashV2::haraka512KeyedFunction)(unsigned char *out, const unsigned char *in, const u128 *rc);
void (*CVerusHashV2::haraka256Function)(unsigned char *out, const unsigned char *in);


// Remove CVerusHash implementation as it's not used for V2+
/*
void CVerusHash::Hash(void *result, const void *data, size_t _len)
{
    unsigned char buf[128];
    unsigned char *bufPtr = buf;
    int nextOffset = 64;
    uint32_t pos = 0, len = _len;
    unsigned char *bufPtr2 = bufPtr + nextOffset;
    unsigned char *ptr = (unsigned char *)data;

    // put our last result or zero at beginning of buffer each time
    memset(bufPtr, 0, 32);

    // digest up to 32 bytes at a time
    for ( ; pos < len; pos += 32)
    {
        if (len - pos >= 32)
        {
            memcpy(bufPtr + 32, ptr + pos, 32);
        }
        else
        {
            int i = (int)(len - pos);
            memcpy(bufPtr + 32, ptr + pos, i);
            memset(bufPtr + 32 + i, 0, 32 - i);
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
    // Always use the portable version for SBF
    haraka512Function = &haraka512_port_zero;
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
            memcpy(curBuf + 32 + curPos, data + pos, room);
            (*haraka512Function)(result, curBuf);
            tmp = curBuf;
            curBuf = result;
            result = tmp;
            pos += room;
            curPos = 0;
        }
        else
        {
            memcpy(curBuf + 32 + curPos, data + pos, len - pos);
            curPos += len - pos;
            pos = len;
        }
    }
    return *this;
}

// Add definition for CVerusHash::Reset
CVerusHash &CVerusHash::Reset()
{
    curBuf = buf1;
    result = buf2;
    curPos = 0;
    memset(buf1, 0, sizeof(buf1));
    return *this;
}

// to be declared and accessed from C
void verus_hash(void *result, const void *data, size_t len)
{
    return CVerusHash::Hash(result, data, len);
}
*/

// Static member definitions are at the top of the file.

void CVerusHashV2::init()
{
    // Portable path is always taken for SBF, IsCPUVerusOptimized() is effectively false.
    // if (IsCPUVerusOptimized()) // Removed conditional logic for SBF
    // {
    //     load_constants();
    //     haraka512Function = &haraka512;
    //     haraka512KeyedFunction = &haraka512_keyed;
    //     haraka256Function = &haraka256;
    // }
    // else
    {
        // load the haraka constants
        load_constants_port();
        haraka512Function = &haraka512_port;
        haraka512KeyedFunction = &haraka512_port_keyed;
        haraka256Function = &haraka256_port;
    }
    // Removed duplicate/erroneous block that checked IsCPUVerusOptimized
    // The portable path logic above is the correct one for SBF.
}

// Renamed Hash method to avoid conflict with CVerusHash if it were present
void CVerusHashV2::Hash_V2(void *result, const void *data, size_t len)
{
    // Align the buffer to 32 bytes, which is usually sufficient for AVX/SIMD instructions.
    alignas(32) unsigned char buf[128];
    unsigned char *bufPtr = buf;
    int nextOffset = 64;
    size_t pos = 0; // Use size_t for position
    unsigned char *bufPtr2 = bufPtr + nextOffset;
    const unsigned char *ptr = (const unsigned char *)data; // Use const pointer

    // put our last result or zero at beginning of buffer each time
    verus_memset(bufPtr, 0, 32);

    // digest up to 32 bytes at a time
    for ( ; pos < len; pos += 32)
    {
        size_t remaining = len - pos; // Use size_t
        size_t chunk_size = (remaining >= 32) ? 32 : remaining; // Use size_t

        verus_memcpy(bufPtr + 32, ptr + pos, chunk_size);
        if (chunk_size < 32)
        {
            verus_memset(bufPtr + 32 + chunk_size, 0, 32 - chunk_size);
        }

        (*haraka512Function)(bufPtr2, bufPtr);
        bufPtr2 = bufPtr;
        bufPtr += nextOffset;
        nextOffset *= -1;
    }
    memcpy(result, bufPtr, 32);
};

CVerusHashV2 &CVerusHashV2::Write(const unsigned char *data, size_t len)
{
    unsigned char *tmp;
    size_t pos = 0; // Use size_t

    // digest up to 32 bytes at a time
    while ( pos < len )
    {
        size_t room = 32 - curPos; // Use size_t
        size_t remaining = len - pos; // Use size_t
        size_t chunk_size = (remaining >= room) ? room : remaining; // Use size_t

        verus_memcpy(curBuf + 32 + curPos, data + pos, chunk_size);

        if (curPos + chunk_size == 32) // Buffer full
        {
            (*haraka512Function)(result, curBuf);
            tmp = curBuf;
            curBuf = result;
            result = tmp;
            curPos = 0;
        }
        else
        {
            curPos += chunk_size;
        }
        pos += chunk_size;
    }
    return *this;
}

// This is the C-callable function
extern "C" void verus_hash_v2(void *result, const void *data, size_t len)
{
    // Call the renamed class method
    CVerusHashV2::Hash_V2(result, data, len);
}

// Initializes the VerusHash V2 library. Must be called once before using verus_hash_v2.
// Definition remains unchanged, but relies on the modified CVerusHashV2::init() above.
extern "C" void verus_hash_v2_init()
{
    CVerusHashV2::init();
}
