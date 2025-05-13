// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uint256.h"
#include "haraka_portable.h" // For verus_memcpy, verus_memset

// #include "utilstrencodings.h" // Removed: SetHex/GetHex and dependencies removed
// #include <stdio.h> // Removed: sprintf removed
// #include <string.h> // For memcmp (compiler builtin usually) // Removed for SBF

// template <unsigned int BITS> // Removed: std::vector
// base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
// {
//     assert(vch.size() == sizeof(data));
//     verus_memcpy(data, &vch[0], sizeof(data));
// }

// template <unsigned int BITS> // Removed: std::string and stdio
// std::string base_blob<BITS>::GetHex() const
// {
//     // char psz[sizeof(data) * 2 + 1];
//     // for (unsigned int i = 0; i < sizeof(data); i++)
//     //     sprintf(psz + i * 2, "%02x", data[sizeof(data) - i - 1]);
//     // return std::string(psz, psz + sizeof(data) * 2);
//     return ""; // Placeholder
// }

// template <unsigned int BITS> // Removed: SetHex and its dependencies (isspace, tolower, HexDigit)
// void base_blob<BITS>::SetHex(const char* psz)
// {
//     // verus_memset(data, 0, sizeof(data));
//     // ...
// }

// template <unsigned int BITS> // Removed: SetHex and std::string
// void base_blob<BITS>::SetHex(const std::string& str)
// {
//     // SetHex(str.c_str());
// }

// template <unsigned int BITS> // Removed: ToString and std::string
// std::string base_blob<BITS>::ToString() const
// {
//     // return (GetHex());
//     return ""; // Placeholder
// }

// Explicit instantiations for base_blob<160>
// template base_blob<160>::base_blob(const std::vector<unsigned char>&); // Removed
// template std::string base_blob<160>::GetHex() const; // Removed
// template std::string base_blob<160>::ToString() const; // Removed
// template void base_blob<160>::SetHex(const char*); // Removed
// template void base_blob<160>::SetHex(const std::string&); // Removed

// Explicit instantiations for base_blob<256>
// template base_blob<256>::base_blob(const std::vector<unsigned char>&); // Removed
// template std::string base_blob<256>::GetHex() const; // Removed
// template std::string base_blob<256>::ToString() const; // Removed
// template void base_blob<256>::SetHex(const char*); // Removed
// template void base_blob<256>::SetHex(const std::string&); // Removed


// base_blob methods that are kept (constructor, IsNull, SetNull, operators, begin, end, size)
// need to be instantiated if they are not defined in the header.
// Constructor, IsNull, SetNull are in header. Operators are inline friend in header.
// begin, end, size are in header.
// GetCheapHash is in header. GetHash is in header but implemented in .cpp.

static void inline HashMix(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    a -= c;
    a ^= ((c << 4) | (c >> 28));
    c += b;
    b -= a;
    b ^= ((a << 6) | (a >> 26));
    a += c;
    c -= b;
    c ^= ((b << 8) | (b >> 24));
    b += a;
    a -= c;
    a ^= ((c << 16) | (c >> 16));
    c += b;
    b -= a;
    b ^= ((a << 19) | (a >> 13));
    a += c;
    c -= b;
    c ^= ((b << 4) | (b >> 28));
    b += a;
}

static void inline HashFinal(uint32_t& a, uint32_t& b, uint32_t& c)
{
    // Taken from lookup3, by Bob Jenkins.
    c ^= b;
    c -= ((b << 14) | (b >> 18));
    a ^= c;
    a -= ((c << 11) | (c >> 21));
    b ^= a;
    b -= ((a << 25) | (a >> 7));
    c ^= b;
    c -= ((b << 16) | (b >> 16));
    a ^= c;
    a -= ((c << 4) | (c >> 28));
    b ^= a;
    b -= ((a << 14) | (a >> 18));
    c ^= b;
    c -= ((b << 24) | (b >> 8));
}

uint64_t uint256::GetHash(const uint256& salt) const
{
    uint32_t a, b, c;
    const uint32_t *pn = (const uint32_t*)data;
    const uint32_t *salt_pn = (const uint32_t*)salt.data;
    a = b = c = 0xdeadbeef + WIDTH;

    a += pn[0] ^ salt_pn[0];
    b += pn[1] ^ salt_pn[1];
    c += pn[2] ^ salt_pn[2];
    HashMix(a, b, c);
    a += pn[3] ^ salt_pn[3];
    b += pn[4] ^ salt_pn[4];
    c += pn[5] ^ salt_pn[5];
    HashMix(a, b, c);
    a += pn[6] ^ salt_pn[6];
    b += pn[7] ^ salt_pn[7];
    HashFinal(a, b, c);

    return ((((uint64_t)b) << 32) | c);
}
