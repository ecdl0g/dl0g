// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include <crypto/common.h>
#include <span.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <array>
#include <assert.h>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <stdint.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>


/** Template base class for fixed-sized opaque blobs. */
template<unsigned int BITS>
class base_blob
{
protected:
    static constexpr int WIDTH = BITS / 8;
    static_assert(BITS % 8 == 0, "base_blob currently only supports whole bytes.");
    std::array<uint8_t, WIDTH> m_data;
    static_assert(WIDTH == sizeof(m_data), "Sanity check");

public:
    /* construct 0 value by default */
    constexpr base_blob() : m_data() {}

    /* constructor for constants between 1 and 255 */
    constexpr explicit base_blob(uint8_t v) : m_data{v} {}

    constexpr explicit base_blob(std::span<const unsigned char> vch)
    {
        assert(vch.size() == WIDTH);
        std::copy(vch.begin(), vch.end(), m_data.begin());
    }

    consteval explicit base_blob(std::string_view hex_str);

    constexpr bool IsNull() const
    {
        return std::all_of(m_data.begin(), m_data.end(), [](uint8_t val) {
            return val == 0;
        });
    }

    constexpr void SetNull()
    {
        std::fill(m_data.begin(), m_data.end(), 0);
    }

    /** Lexicographic ordering
     * @note Does NOT match the ordering on the corresponding \ref
     *       base_uint::CompareTo, which starts comparing from the end.
     */
    constexpr int Compare(const base_blob& other) const { return std::memcmp(m_data.data(), other.m_data.data(), WIDTH); }

    friend constexpr bool operator==(const base_blob& a, const base_blob& b) { return a.Compare(b) == 0; }
    friend constexpr bool operator!=(const base_blob& a, const base_blob& b) { return a.Compare(b) != 0; }
    friend constexpr bool operator<(const base_blob& a, const base_blob& b) { return a.Compare(b) < 0; }

    /** @name Hex representation
     *
     * The hex representation used by GetHex(), ToString(), FromHex() and
     * SetHexDeprecated() is unusual, since it shows bytes of the base_blob in
     * reverse order. For example, a 4-byte blob {0x12, 0x34, 0x56, 0x78} is
     * represented as "78563412" instead of the more typical "12345678"
     * representation that would be shown in a hex editor or used by typical
     * byte-array / hex conversion functions like python's bytes.hex() and
     * bytes.fromhex().
     *
     * The nice thing about the reverse-byte representation, even though it is
     * unusual, is that if a blob contains an arithmetic number in little endian
     * format (with least significant bytes first, and most significant bytes
     * last), the GetHex() output will match the way the number would normally
     * be written in base-16 (with most significant digits first and least
     * significant digits last).
     *
     * This means, for example, that ArithToUint256(num).GetHex() can be used to
     * display an arith_uint256 num value as a number, because
     * ArithToUint256() converts the number to a blob in little-endian format,
     * so the arith_uint256 class doesn't need to have its own number parsing
     * and formatting functions.
     *
     * @{*/
    std::string GetHex() const;
    /** Unlike FromHex this accepts any invalid input, thus it is fragile and deprecated!
     *
     * - Hex numbers that don't specify enough bytes to fill the internal array
     *   will be treated as setting the beginning of it, which corresponds to
     *   the least significant bytes when converted to base_uint.
     *
     * - Hex numbers specifying too many bytes will have the numerically most
     *   significant bytes (the beginning of the string) narrowed away.
     *
     * - An odd count of hex digits will result in the high bits of the leftmost
     *   byte being zero.
     *   "0x123" => {0x23, 0x1, 0x0, ..., 0x0}
     */
    void SetHexDeprecated(std::string_view str);
    std::string ToString() const;
    /**@}*/

    constexpr const unsigned char* data() const { return m_data.data(); }
    constexpr unsigned char* data() { return m_data.data(); }

    constexpr unsigned char* begin() { return m_data.data(); }
    constexpr unsigned char* end() { return m_data.data() + WIDTH; }

    constexpr const unsigned char* begin() const { return m_data.data(); }
    constexpr const unsigned char* end() const { return m_data.data() + WIDTH; }

    static constexpr unsigned int size() { return WIDTH; }

    constexpr uint64_t GetUint64(int pos) const { return ReadLE64(m_data.data() + pos * 8); }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s << std::span(m_data);
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read(MakeWritableByteSpan(m_data));
    }
};

template <unsigned int BITS>
consteval base_blob<BITS>::base_blob(std::string_view hex_str)
{
    if (hex_str.length() != m_data.size() * 2) throw "Hex string must fit exactly";
    auto str_it = hex_str.rbegin();
    for (auto& elem : m_data) {
        auto lo = util::ConstevalHexDigit(*(str_it++));
        elem = (util::ConstevalHexDigit(*(str_it++)) << 4) | lo;
    }
}

namespace detail {
/**
 * Writes the hex string (in reverse byte order) into a new uintN_t object
 * and only returns a value iff all of the checks pass:
 *   - Input length is uintN_t::size()*2
 *   - All characters are hex
 */
template <class uintN_t>
std::optional<uintN_t> FromHex(std::string_view str)
{
    if (uintN_t::size() * 2 != str.size() || !IsHex(str)) return std::nullopt;
    uintN_t rv;
    rv.SetHexDeprecated(str);
    return rv;
}
/**
 * @brief Like FromHex(std::string_view str), but allows an "0x" prefix
 *        and pads the input with leading zeroes if it is shorter than
 *        the expected length of uintN_t::size()*2.
 *
 *        Designed to be used when dealing with user input.
 */
template <class uintN_t>
std::optional<uintN_t> FromUserHex(std::string_view input)
{
    input = util::RemovePrefixView(input, "0x");
    constexpr auto expected_size{uintN_t::size() * 2};
    if (input.size() < expected_size) {
        auto padded = std::string(expected_size, '0');
        std::copy(input.begin(), input.end(), padded.begin() + expected_size - input.size());
        return FromHex<uintN_t>(padded);
    }
    return FromHex<uintN_t>(input);
}
} // namespace detail

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160> {
public:
    static std::optional<uint160> FromHex(std::string_view str) { return detail::FromHex<uint160>(str); }
    constexpr uint160() = default;
    constexpr explicit uint160(std::span<const unsigned char> vch) : base_blob<160>(vch) {}
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256> {
public:
    static std::optional<uint256> FromHex(std::string_view str) { return detail::FromHex<uint256>(str); }
    static std::optional<uint256> FromUserHex(std::string_view str) { return detail::FromUserHex<uint256>(str); }
    constexpr uint256() = default;
    consteval explicit uint256(std::string_view hex_str) : base_blob<256>(hex_str) {}
    constexpr explicit uint256(uint8_t v) : base_blob<256>(v) {}
    constexpr explicit uint256(std::span<const unsigned char> vch) : base_blob<256>(vch) {}
    static const uint256 ZERO;
    static const uint256 ONE;
};

/** 1024-bit opaque blob.
 */
class uint1280 {
    private:
        //Internal data chosen as 64-bits to align with GMP limbs as 64 bits.
        const int32_t LIMBS = 20;  //1280-bits


    public:

    uint64_t _data[20] = {0};

    uint1280() = default;
    uint1280(const uint1280& other)
    {
        memcpy(_data, other._data, sizeof(_data));
    }

    //In place shift operator.
    uint1280 operator<<(const uint32_t bitshift )
    {
        assert(bitshift < static_cast<uint32_t>(LIMBS * 64));
        uint32_t qwordShift = bitshift >> 6;
        uint32_t bShift     = bitshift & 0x3f;
        int32_t topLimb     = LIMBS - 1 - qwordShift ;

        //Shift final values into place
        for( int32_t jj = topLimb; jj > 0 ; jj--){

            uint64_t current_limb = _data[ jj     ] << bShift;
            uint64_t prev_limb    = (bShift==0) ? 0 : _data[ jj - 1 ] >> (64 - bShift);
            _data[ qwordShift + jj] = current_limb | prev_limb;
        }

        //Do last limb
        _data[ qwordShift ] =  _data[0] << bShift;

        //Set words to zero
        for( uint32_t jj=0; jj < qwordShift; jj++)  _data[jj] = 0;

        return *this;
    }

    // copy assignment
    uint1280& operator=(const uint1280& other)
    {
        // Guard self assignment
        if (this == &other)
            return *this;

        //Copy the data
        memcpy( _data, other.u8_begin_write(), sizeof(_data) );
        return *this;
    }

    //Get pointer to the beginning of the data
    const uint64_t* u64_begin() const
    {
        return _data;
    }

    //Get pointer to the end of the data
    const uint64_t* u64_end() const
    {
        return &_data[LIMBS-1 ] ;
    }

    //Get pointer to the beginning of the data
    const uint8_t* u8_begin() const
    {
        return (uint8_t*)_data;
    }

    //Get pointer to the beginning of the data
    uint8_t* u8_begin_write() const
    {
        return (uint8_t*)_data;
    }

    //Get pointer to the end of the data
    const uint8_t* u8_end() const
    {
        return &((uint8_t*)_data)[ sizeof(_data) - 1 ] ;
    }

    void SetNull()
    {
        memset(_data, 0, sizeof(_data) );
    }

    std::string ToString() const
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < LIMBS; ++i)
        {
            ss << std::setw(16) << _data[LIMBS - i - 1];
        }
        return ss.str();
    }

    // Returns the A value in y^2 = x^3 + Ax + B Mod P
    // Stored as the first 256 bits in an uint1280 type.
    std::string GetA() const 
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 4; ++i)
        {
            ss << std::setw(16) << _data[LIMBS - i - 1];
        }
        return ss.str();
    }

    // Returns the B value in y^2 = x^3 + Ax + B Mod P
    // Stored as the second block of 256 bits in 
    // an uint1280 type.
    std::string GetB() const 
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 4; i < 8; ++i)
        {
            ss << std::setw(16) << _data[LIMBS - i - 1];
        }
        return ss.str();
    }

    // Returns the P value in y^2 = x^3 + Ax + B Mod P
    // Stored as the third block of 256 bits in 
    // an uint1280 type.
    std::string GetP() const 
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 8; i < 12; ++i)
        {
            ss << std::setw(16) << _data[LIMBS - i - 1];
        }
        return ss.str();
    }

    // Returns the x0 value of random point on 
    // y^2 = x^3 + Ax + B Mod P
    // Stored as the fourtth block of 256 bits in 
    // an uint1280 type.
    std::string GetX() const 
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 12; i < 16; ++i)
        {
            ss << std::setw(16) << _data[LIMBS - i - 1];
        }
        return ss.str();
    }

    // Returns the x1 value of random point on 
    // y^2 = x^3 + Ax + B Mod P
    // Stored as the fourtth block of 256 bits in 
    // an uint1280 type.
    std::string GetXG() const 
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 16; i < 20; ++i)
        {
            ss << std::setw(16) << _data[LIMBS - i - 1];
        }
        return ss.str();
    }

    void SetHex(const char* psz);
    void SetHex(const std::string& str);

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write((char*)_data, sizeof(_data));
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read((char*)_data, sizeof(_data));
    }

    uint64_t bits() const
    {
            const int64_t WIDTH = 1024/64;
        for (int pos = WIDTH - 1; pos >= 0; pos--) {
            if (_data[pos]) {
                for (int nbits = 63; nbits >= 0; nbits--) {
                    if (_data[pos] & 1ULL << nbits)
                        return 64 * pos + nbits + 1 ;
                }
                return 64 * pos ;
            }
        }
        return 0;
    }
};

/* uint1280 from const char *.
 * This is a separate function because the constructor uint1280(const char*) can result
 * in dangerously catching uint1280(0).
 */
inline uint1280 uint1280S(const char *str)
{
    uint1280 rv;
    rv.SetHex(str);
    return rv;
}
/* uint1280S from std::string.
 * This is a separate function because the constructor uint256(const std::string &str) can result
 * in dangerously catching uint1280(0) via std::string(const char*).
 */
inline uint1280 uint1280S(const std::string& str)
{
    uint1280 rv;
    rv.SetHex(str);
    return rv;
}



#endif // BITCOIN_UINT256_H
