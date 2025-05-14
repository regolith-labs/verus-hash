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

// <cstring> removed. size_t and NULL are now provided by haraka_portable.h for BPF.
// #include <vector> // Removed, ensure no std::vector usage remains or is BPF-compatible.

#include "uint256.h"
#include "verus_clhash.h" // Still needed for verusclhasher type, constructor will be conditional
#include "haraka_portable.h" // For verus_memset, verus_memcpy, size_t, NULL

extern "C" 
{
#ifdef VERUS_BPF_TARGET
    // For BPF, only haraka_portable.h is needed for type definitions and portable function declarations.
    // It will define __m128i and u128 in a BPF-compatible way.
    #include "haraka_portable.h"
#else
    // For HOST, include haraka.h first (which includes immintrin.h and defines u128 from the intrinsic __m128i).
    // Then include haraka_portable.h (which will also include immintrin.h - guarded - and re-typedef u128, which is fine).
    #include "haraka.h"
    #include "haraka_portable.h"
#endif
}

class CVerusHash
{
    public:
        static void Hash(void *result, const void *data, size_t len);
        static void (*haraka512Function)(unsigned char *out, const unsigned char *in);

        static void init();

        CVerusHash() { }

        CVerusHash &Write(const unsigned char *data, size_t len);

        CVerusHash &Reset()
        {
            curBuf = buf1;
            result = buf2;
            curPos = 0;
            verus_memset(buf1, 0, sizeof(buf1));
            return *this;
        }

        int64_t *ExtraI64Ptr() { return (int64_t *)(curBuf + 32); }
        void ClearExtra()
        {
            if (curPos)
            {
                // Length is (curBuf + 64) - (curBuf + 32 + curPos) = 32 - curPos
                verus_memset(curBuf + 32 + curPos, 0, 32 - curPos);
            }
        }
        void ExtraHash(unsigned char hash[32]) { (*haraka512Function)(hash, curBuf); }

        void Finalize(unsigned char hash[32])
        {
            if (curPos)
            {
                verus_memset(curBuf + 32 + curPos, 0, 32 - curPos);
                (*haraka512Function)(hash, curBuf);
            }
            else
                verus_memcpy(hash, curBuf, 32);
        }

    private:
        // only buf1, the first source, needs to be zero initialized
        alignas(32) unsigned char buf1[64] = {0}; // Ensure alignment for Haraka
        alignas(32) unsigned char buf2[64];
        unsigned char *curBuf = buf1, *result = buf2;
        size_t curPos = 0;
};

class CVerusHashV2
{
    public:
        static void Hash(void *result, const void *data, size_t len);
        static void (*haraka512Function)(unsigned char *out, const unsigned char *in);
        static void (*haraka512KeyedFunction)(unsigned char *out, const unsigned char *in, const u128 *rc);
        static void (*haraka256Function)(unsigned char *out, const unsigned char *in);

        static void init();

#if !defined(VERUS_FORCE_PORTABLE_IMPL) && !defined(VERUS_BPF_TARGET)
        verusclhasher vclh;
#endif

        CVerusHashV2(int solutionVersion=SOLUTION_VERUSHHASH_V2)
#if !defined(VERUS_FORCE_PORTABLE_IMPL) && !defined(VERUS_BPF_TARGET)
        // Initialize vclh only if not portable and not targeting BPF
        : vclh(VERUSKEYSIZE, solutionVersion)
#endif
        {
#if !defined(VERUS_FORCE_PORTABLE_IMPL) && !defined(VERUS_BPF_TARGET)
            // we must have allocated key space, or can't run
            // This check relies on verusclhasher_key which is thread_local
            if (!verusclhasher_key.get())
            {
                // printf("ERROR: failed to allocate hash buffer - terminating\n"); // BPF: no printf
                // assert(false); // BPF: no assert
            }
#else
            // Portable or BPF target: vclh is not initialized here.
            (void)solutionVersion; // Suppress unused parameter warning
#endif
        }

        CVerusHashV2 &Write(const unsigned char *data, size_t len);

        inline CVerusHashV2 &Reset()
        {
            curBuf = buf1;
            result = buf2;
            curPos = 0;
            verus_memset(buf1, 0, sizeof(buf1));
            return *this;
        }

        inline int64_t *ExtraI64Ptr() { return (int64_t *)(curBuf + 32); }
        inline void ClearExtra()
        {
            if (curPos)
            {
                verus_memset(curBuf + 32 + curPos, 0, 32 - curPos);
            }
        }

#ifndef VERUS_BPF_TARGET // These methods depend on vclh or complex key generation
        template <typename T>
        inline void FillExtra(const T *_data)
        {
            unsigned char *data = (unsigned char *)_data;
            int pos = curPos;
            int left = 32 - pos;
            do
            {
                int len = left > (int)sizeof(T) ? (int)sizeof(T) : left; // cast sizeof to int for comparison
                verus_memcpy(curBuf + 32 + pos, data, len);
                pos += len;
                left -= len;
            } while (left > 0);
        }
        inline void ExtraHashKeyed(unsigned char hash[32], u128 *key) { (*haraka512KeyedFunction)(hash, curBuf, key); }
#endif // VERUS_BPF_TARGET

    // Methods ONLY for non-portable AND non-BPF (these use vclh, verusclhasher_key, etc.)
#if !defined(VERUS_FORCE_PORTABLE_IMPL) && !defined(VERUS_BPF_TARGET)
        // chains Haraka256 from 32 bytes to fill the key
        static u128 *GenNewCLKey(unsigned char *seedBytes32)
        {
            unsigned char *key = (unsigned char *)verusclhasher_key.get();
            verusclhash_descr *pdesc = (verusclhash_descr *)verusclhasher_descr.get();
            int size = pdesc->keySizeInBytes;
            int refreshsize = verusclhasher::keymask(size) + 1;
            // skip keygen if it is the current key
            if (pdesc->seed != *((uint256 *)seedBytes32))
            {
                // generate a new key by chain hashing with Haraka256 from the last curbuf
                int n256blks = size >> 5;
                int nbytesExtra = size & 0x1f;
                unsigned char *pkey = key;
                unsigned char *psrc = seedBytes32;
                for (int i = 0; i < n256blks; i++)
                {
                    (*haraka256Function)(pkey, psrc);
                    psrc = pkey;
                    pkey += 32;
                }
                if (nbytesExtra)
                {
                    unsigned char buf[32];
                    (*haraka256Function)(buf, psrc);
                    verus_memcpy(pkey, buf, nbytesExtra);
                }
                pdesc->seed = *((uint256 *)seedBytes32);
                verus_memcpy(key + size, key, refreshsize);
            }
            else
            {
                verus_memcpy(key, key + size, refreshsize);
            }

            verus_memset((unsigned char *)key + (size + refreshsize), 0, size - refreshsize);
            return (u128 *)key;
        }

        inline uint64_t IntermediateTo128Offset(uint64_t intermediate)
        {
            // the mask is where we wrap
            uint64_t mask = vclh.keyMask >> 4;
            return intermediate & mask;
        }

        void Finalize2b(unsigned char hash[32])
        {
            // fill buffer to the end with the beginning of it to prevent any foreknowledge of
            // bits that may contain zero
            FillExtra((u128 *)curBuf);


            // gen new key with what is last in buffer
            u128 *key = GenNewCLKey(curBuf);

            // run verusclhash on the buffer
            uint64_t intermediate = vclh(curBuf, key);

            // fill buffer to the end with the result
            FillExtra(&intermediate);

            // get the final hash with a mutated dynamic key for each hash result
            (*haraka512KeyedFunction)(hash, curBuf, key + IntermediateTo128Offset(intermediate));
        }
#endif // !defined(VERUS_FORCE_PORTABLE_IMPL) && !defined(VERUS_BPF_TARGET)

        // This version of ExtraHash is always available
        inline void ExtraHash(unsigned char hash[32]) { (*haraka512Function)(hash, curBuf); }

        void Finalize(unsigned char hash[32])
        {
            if (curPos)
            {
                verus_memset(curBuf + 32 + curPos, 0, 32 - curPos);
                (*haraka512Function)(hash, curBuf);
            }
            else
                verus_memcpy(hash, curBuf, 32);
        }

        inline unsigned char *CurBuffer()
        {
            return curBuf;
        }

    private:
        // only buf1, the first source, needs to be zero initialized
        alignas(32) unsigned char buf1[64] = {0};
        alignas(32) unsigned char buf2[64];
        unsigned char *curBuf = buf1, *result = buf2;
        size_t curPos = 0;
};

extern void verus_hash(void *result, const void *data, size_t len);
extern void verus_hash_v2(void *result, const void *data, size_t len);

#endif
