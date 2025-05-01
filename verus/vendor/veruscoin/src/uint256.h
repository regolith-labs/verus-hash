// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

// #include <assert.h> // Removed: Not available in SBF
// #include <cstring> // Removed: Not available in SBF, use haraka_portable.h declarations
// #include <stdexcept> // Removed: Not available in SBF (-nostdlib++)
#include <stdint.h>
// #include <string> // Removed: Not available in SBF (-nostdlib++)
// #include <vector> // Removed: Not available in SBF (-nostdlib++)

/** Template base class for fixed-sized opaque blobs. */
template<unsigned int BITS>
class base_blob
{
protected:
    enum { WIDTH=BITS/8 };
    alignas(uint32_t) uint8_t data[WIDTH];
public:
    base_blob()
    {
        memset(data, 0, sizeof(data));
    }

    // explicit base_blob(const std::vector<unsigned char>& vch); // Removed: Uses std::vector

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (data[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(data, 0, sizeof(data));
    }

    friend inline bool operator==(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) == 0; }
    friend inline bool operator!=(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) != 0; }
    friend inline bool operator<(const base_blob& a, const base_blob& b) { return memcmp(a.data, b.data, sizeof(a.data)) < 0; }

    // std::string GetHex() const; // Removed: Uses std::string
    // void SetHex(const char* psz); // Removed: Uses std::string
    // void SetHex(const std::string& str); // Removed: Uses std::string
    // std::string ToString() const; // Removed: Uses std::string

    unsigned char* begin()
    {
        return &data[0];
    }

    unsigned char* end()
    {
        return &data[WIDTH];
    }

    const unsigned char* begin() const
    {
        return &data[0];
    }

    const unsigned char* end() const
    {
        return &data[WIDTH];
    }

    unsigned int size() const
    {
        return sizeof(data);
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write((char*)data, sizeof(data));
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read((char*)data, sizeof(data));
    }
};

/** 88-bit opaque blob.
 */
class blob88 : public base_blob<88> {
public:
    blob88() {}
    blob88(const base_blob<88>& b) : base_blob<88>(b) {}
    // explicit blob88(const std::vector<unsigned char>& vch) : base_blob<88>(vch) {} // Removed: Uses std::vector
};

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    uint160() {}
    uint160(const base_blob<160>& b) : base_blob<160>(b) {}
    // explicit uint160(const std::vector<unsigned char>& vch) : base_blob<160>(vch) {} // Removed: Uses std::vector
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    uint256() {}
    uint256(const base_blob<256>& b) : base_blob<256>(b) {}
    // explicit uint256(const std::vector<unsigned char>& vch) : base_blob<256>(vch) {} // Removed: Uses std::vector

    /** A cheap hash function that just returns 64 bits from the result, it can be
     * used when the contents are considered uniformly random. It is not appropriate
     * when the value can easily be influenced from outside as e.g. a network adversary could
     * provide values to trigger worst-case behavior.
     * @note The result of this function is not stable between little and big endian.
     */
    uint64_t GetCheapHash() const
    {
        uint64_t result;
        memcpy((void*)&result, (void*)data, 8);
        return result;
    }

    /** A more secure, salted hash function.
     * @note This hash is not stable between little and big endian.
     */
    // uint64_t GetHash(const uint256& salt) const; // Removed: Unused and might have stdlib dependencies
};

// Removed uint256S helper functions as they depend on SetHex/std::string
// Removed LEGACY_TX_AUTH_DIGEST as it depends on uint256S

#endif // BITCOIN_UINT256_H
