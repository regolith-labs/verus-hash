// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "uint256.h"

// #include "utilstrencodings.h" // Removed: Not needed for SBF, depends on std::string
// #include <stdio.h> // Removed: Not needed for SBF
// #include <string.h> // Removed: Use haraka_portable.h declarations

// Include necessary headers for SBF compatibility
#include "haraka_portable.h" // Provides memcpy, memset, memcmp

// Removed base_blob constructor taking std::vector
// Removed GetHex, SetHex, ToString methods (depend on std::string, stdio)
// Removed explicit instantiations for removed methods

// Explicit instantiations for base_blob - needed for linking if used elsewhere,
// but the constructor taking std::vector is removed.
// Keep template definitions in header, remove explicit instantiations from .cpp
// template base_blob<160>::base_blob(const std::vector<unsigned char>&);
// template base_blob<256>::base_blob(const std::vector<unsigned char>&);


// Removed HashMix, HashFinal, and GetHash as they are unused in the SBF context
// and GetHash was commented out in the header.
