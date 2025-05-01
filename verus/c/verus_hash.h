// (C) 2018 Michael Toutonghi
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
This provides the PoW hash function for Verus, enabling CPU mining.
*/
#ifndef VERUS_HASH_H_
#define VERUS_HASH_H_

// verbose output when defined
//#define VERUSHASHDEBUG 1

// #include <cstring> // Removed: Use haraka_portable implementations
// #include <vector>  // Removed: Not used in V2 path

#include "uint256.h"
// #include "verus_clhash.h" // Removed: Not needed for portable Haraka path

// Wrap C headers/functions in extern "C" when included from C++
#ifdef __cplusplus
extern "C" {
#endif

#include "haraka_portable.h" // Added: Provides memcpy/memset for SBF and u128 type

#ifdef __cplusplus
} // extern "C"
#endif

// Removed extern "C" block around haraka_portable.h include, it's a C++ header now
// extern "C"
// {
// #include "crypto/haraka.h" // Removed: Causes x86 intrinsic errors on BPF target
// #include "haraka_portable.h" // Already included above
// }

// Removed CVerusHash class definition as it's unused for V2+
/*
class CVerusHash
{
    // ... (contents removed) ...
};
*/

class CVerusHashV2
{
    public:
        // Renamed static Hash method to avoid potential conflicts
        static void Hash_V2(void *result, const void *data, size_t len);
        static void (*haraka512Function)(unsigned char *out, const unsigned char *in);
        static void (*haraka512KeyedFunction)(unsigned char *out, const unsigned char *in, const u128 *rc);
        static void (*haraka256Function)(unsigned char *out, const unsigned char *in);

        static void init();

        // verusclhasher vclh; // Removed: CLHASH not used in portable SBF build path

        CVerusHashV2() {
            // Default constructor, no CLHASH initialization needed
        }

        CVerusHashV2 &Write(const unsigned char *data, size_t len);

        inline CVerusHashV2 &Reset()
        {
            curBuf = buf1;
            result = buf2;
            curPos = 0;
            // std::fill(buf1, buf1 + sizeof(buf1), 0); // Replaced with verus_memset
            verus_memset(buf1, 0, sizeof(buf1));
            return *this;
        }

        inline int64_t *ExtraI64Ptr() { return (int64_t *)(curBuf + 32); }
        inline void ClearExtra()
        {
            if (curPos)
            {
                // std::fill(curBuf + 32 + curPos, curBuf + 64, 0); // Replaced with verus_memset
                verus_memset(curBuf + 32 + curPos, 0, 64 - (32 + curPos));
            }
        }

        template <typename T>
        inline void FillExtra(const T *_data)
        {
            unsigned char *data = (unsigned char *)_data;
            int pos = curPos;
            int left = 32 - pos;
            do
            {
                int len = left > sizeof(T) ? sizeof(T) : left;
                // Use our declared verus_memcpy
                verus_memcpy(curBuf + 32 + pos, data, len);
                pos += len;
                left -= len;
            } while (left > 0);
        }
        inline void ExtraHash(unsigned char hash[32]) { (*haraka512Function)(hash, curBuf); }
        inline void ExtraHashKeyed(unsigned char hash[32], u128 *key) { (*haraka512KeyedFunction)(hash, curBuf, key); }

        void Finalize(unsigned char hash[32])
        {
            if (curPos)
            {
                // std::fill(curBuf + 32 + curPos, curBuf + 64, 0); // Replaced with verus_memset
                verus_memset(curBuf + 32 + curPos, 0, 64 - (32 + curPos));
                (*haraka512Function)(hash, curBuf);
            }
            else
                // Use our declared verus_memcpy
                verus_memcpy(hash, curBuf, 32);
        }

        // Removed CLHASH-dependent methods: GenNewCLKey, IntermediateTo128Offset, Finalize2b

        inline unsigned char *CurBuffer()
        {
            return curBuf;
        }

    private:
        // only buf1, the first source, needs to be zero initialized
        alignas(32) unsigned char buf1[64] = {0}, buf2[64];
        unsigned char *curBuf = buf1, *result = buf2;
        size_t curPos = 0;
};

// Moved extern "C" block outside class definitions
extern "C" {
    // Removed verus_hash declaration (unused V1)
    // void verus_hash(void *result, const void *data, size_t len);
    void verus_hash_v2(void *result, const void *data, size_t len);
    // Function to initialize the VerusHash V2 library internals.
    void verus_hash_v2_init();
}

#endif
