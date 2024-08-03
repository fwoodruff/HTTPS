//
//  bignum.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 05/12/2021.
//

#ifndef bignum_hpp
#define bignum_hpp

#include <cassert>
#include <array>
#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <climits>
#include <cstdint>

namespace fbw {
/*
 Specialised big number library
 Unsigned only
 Operations are not constant time but should be
 
 Addition and subtraction wrap on overflow
 Multiplication and division change width so do not overflow.
 
 Friends with 'REDC' functions.
 REDC_P(X) efficiently calculates (X * modular_inverse(R)) mod P
 P is some compile-time prime number
 R some power of 2, here 2**256.
 */

template<int INTBITS >
class uVar;

using ct_u256 = uVar<256>;
using ct_u512 = uVar<512>;
using ct_u768 = uVar<768>;
using ct_u1024 = uVar<1024>;

namespace curve25519{ constexpr ct_u256 REDC(ct_u512 aR) noexcept;}
namespace cha { constexpr uVar<192> REDCpoly(uVar<384> aR) noexcept;}


template<int INTBITS >
class uVar {
public:
#ifdef __SIZEOF_INT128__
    using radix = uint64_t;
    using radix2 = __uint128_t;
#else
    using radix = uint32_t;
    using radix2 = uint64_t;
#endif
//private: // Linux doesn't like this template friend trick so must expose as public
    constexpr static int RADIXBITS = sizeof(radix) * CHAR_BIT;
    constexpr static int INTBYTES = (INTBITS + CHAR_BIT - 1)/CHAR_BIT;
    template<int b = INTBITS>
    constexpr static int INTRADICES = (b + RADIXBITS - 1) /RADIXBITS;
    using rep = std::array<radix, INTRADICES<INTBITS> >;
    rep v {0};
public:
    template<int bitsv> friend class uVar;
    
    template<int LBITS > constexpr explicit operator uVar<LBITS>() const noexcept {
        uVar<LBITS> out {};
        for(size_t i = 0; i < std::min(out.v.size(), v.size()); i++) {
            out.v[i] = v[i];
        }
        return out;
    }
    friend std::ostream& operator<<(std::ostream& os, const uVar& dt) {
        std::stringstream oss;
        oss << "0x";
        assert(dt.v.size() >= 1);
        for(long i = dt.v.size()-1; i >=0 ; i--) {
            for(long j = 2 * sizeof(radix)-1; j >= 0; j--) {
                unsigned long x = (dt.v[i] & (0xfULL << (4*j))) >> (4*j);
                oss << std::hex << x;
            }
        }
        os << oss.str();
        return os;
    }
    constexpr std::array<unsigned char, INTBYTES> serialise() const noexcept { // bigendian
        std::array<unsigned char,INTBYTES> out {0};
        constexpr int sr = sizeof(radix);
        for(size_t i = 0; i < v.size(); i++) {
            for(int j = 0; j < sr; j++) {
                out[i*sr +j] = v[i] >> (j*CHAR_BIT);
            }
        }
        std::reverse(out.begin(),out.end()); // to bigendian
        return out;
    }
    constexpr std::array<unsigned char, INTBYTES> serialise_le() const noexcept {
        std::array<unsigned char,INTBYTES> out {0};
        constexpr int sr = sizeof(radix);
        for(size_t i = 0; i < v.size(); i++) {
            for(int j = 0; j < sr; j++) {
                out[i*sr +j] = v[i] >> (j*CHAR_BIT);
            }
        }
        return out;
    }

    constexpr uVar() noexcept :v ({0}) {}
    constexpr uVar(std::string_view s) noexcept {
        assert(s.size() >= 2);
        assert(s[0]== '0' and s[1]=='x');
        assert(s.size() <= INTBITS+2);
        constexpr int hexbits = 4;
        int rchars = RADIXBITS /hexbits;
        for(long i = s.size()-1, x=0; i >=2; i--, x++) {
            assert((s[i] >= '0' and s[i]<='9') or (s[i] >= 'a' ));
            static_assert('a' > '0');
            radix intval = (s[i] >= 'a') ? (s[i] - 'a' + 10) : (s[i] - '0');
            radix mod = intval << ((hexbits*x)%RADIXBITS);
            v[x/rchars] += mod;
        }
    }
    constexpr uVar(std::array<unsigned char, INTBYTES> s) noexcept {
        std::reverse(s.begin(), s.end());
        for(size_t i = 0; i < v.size(); i++) {
            for(size_t j = 0; j < sizeof(radix); j++) {
                radix x = s[i*sizeof(radix) +j];
                v[i] |= (x << (j*CHAR_BIT));
            }
        }
    }
    constexpr uVar& operator+=(const uVar& rhs) noexcept {
        
        radix carry = 0;
        for(size_t i = 0; i < v.size(); i++) {
            const radix2 c = static_cast<radix2>(v[i]) + static_cast<radix2>(rhs.v[i]) + static_cast<radix2>(carry);
            carry = (c >> RADIXBITS);
            v[i] = static_cast<radix>(c);
        }
        return *this;
    }
    constexpr uVar& operator-=(const uVar& rhs) noexcept {
        radix carry = 0;
        for(size_t i = 0; i < v.size(); i++) {
            const radix2 c = static_cast<radix2>(v[i]) + static_cast<radix2>(~rhs.v[i])
                            + static_cast<radix2>(i==0) + static_cast<radix2>(carry);
            carry = c >> RADIXBITS;
            v[i] = static_cast<radix>(c);
        }
        return *this;
    }
    constexpr uVar& operator&=(const uVar& rhs) noexcept {
        for(size_t i = 0; i < v.size(); i++) {
            v[i] &= rhs.v[i];
        }
        return *this;
    }
    constexpr uVar& operator|=(const uVar& rhs) noexcept {
        for(size_t i = 0; i < v.size(); i++) {
            v[i] |= rhs.v[i];
        }
        return *this;
    }
    constexpr uVar& operator^=(const uVar& rhs) noexcept {
        for(size_t i = 0; i < v.size(); i++) {
            v[i] ^= rhs.v[i];
        }
        return *this;
    }

    constexpr uVar& operator>>=(unsigned rhs) noexcept { // ct when rhs is const
        if(rhs >= INTBITS) [[unlikely]] {
            v = {};
            return *this;
        }
        const int bits = rhs % RADIXBITS;
        const size_t blocks = rhs / RADIXBITS;

        radix mask = 0;
        if(bits!=0) {
            mask = (static_cast<radix>(-1ULL)) << (RADIXBITS-bits);
        }
        assert(v.size() >= blocks + 1);
        for(size_t i = 0; i < v.size()-blocks-1; i ++) {
            radix fromsame = v[i+blocks] >> bits;
            radix fromnext = 0;
            if(bits!=0) {
                fromnext = mask & (v[i+blocks+1] << (RADIXBITS-bits));
            }
            v[i] = fromsame | fromnext;
        }
        assert(v.size() >= blocks+1);
        v[v.size()-blocks-1] = v[v.size()-1] >> bits;
        for(size_t i = v.size()-blocks; i < v.size(); i ++) {
            v[i] = 0;
        }
        return *this;
    }
    constexpr uVar& operator<<=(unsigned rhs) noexcept {
        if(rhs >= INTBITS) {
            v = {};
            return *this;
        }
        int bits = rhs % RADIXBITS;
        ssize_t blocks = rhs / RADIXBITS;
        radix mask = 0;
        if(bits != 0) {
            mask = (static_cast<radix>(0)-1) >> (RADIXBITS-bits);
        }
        assert(v.size() >= 1);
        for(ssize_t i = v.size()-1; i > blocks; i--) {
            radix fromsame = v[i-blocks] << bits;
            radix fromnext = 0;
            if(bits!=0) {
                fromnext = (mask & v[i-blocks-1] >> (RADIXBITS - bits));
            }
            v[i] = fromsame | fromnext;
        }
        v[blocks] = v[0] << bits;
        for(ssize_t i = blocks-1; i >= 0; i--) {
            v[i] = 0;
        }
        return *this;
    }
    constexpr uVar operator-() const noexcept {
        uVar out;
        out -= *this;
        return out;
    }
    constexpr uVar operator~() const noexcept {
        uVar out;
        for(size_t i = 0; i < v.size(); i++) {
            out.v[i] = ~v[i];
        }
        return out;
    }
    constexpr friend uVar operator+(uVar lhs, const uVar& rhs) noexcept {
        lhs += rhs;
        return lhs;
    }
    constexpr friend uVar operator-(uVar lhs, const uVar& rhs) noexcept {
        lhs -= rhs;
        return lhs;
    }
    constexpr friend uVar operator&(uVar lhs, const uVar& rhs) noexcept {
        lhs &= rhs;
        return lhs;
    }
    constexpr friend uVar operator|(uVar lhs, const uVar& rhs) noexcept {
        lhs |= rhs;
        return lhs;
    }
    constexpr friend uVar operator^(uVar lhs, const uVar& rhs) noexcept {
        lhs ^= rhs;
        return lhs;
    }
    constexpr friend uVar operator>>(uVar lhs, int rhs) noexcept {
        lhs >>= rhs;
        return lhs;
    }
    constexpr friend uVar operator<<(uVar lhs, int rhs) noexcept {
        lhs <<= rhs;
        return lhs;
    }
    constexpr bool operator==(const uVar &b) const noexcept {
        bool equal = true;
        for(size_t i = 0; i < v.size(); i++) {
            equal = equal and v[i] == b.v[i];
        }
        return equal;
    }
    constexpr bool operator>(const uVar &rhs) const noexcept {
        bool ret = false;
        bool ina = true;
        bool outa = true;
        assert(v.size() >= 1);
        for(ssize_t i = v.size() -1 ; i >= 0; i--) {
            ina &= (v[i]==rhs.v[i]);
            ret |= (v[i] > rhs.v[i]) and (ina != outa);
            outa = ina;
        }
        return ret;
    }
    constexpr bool operator!=(const uVar &b) const noexcept { return !(*this == b); }
    constexpr bool operator<(const uVar &b) const noexcept { return b > *this; }
    constexpr bool operator>=(const uVar &b) const noexcept { return !(b > *this); }
    constexpr bool operator<=(const uVar &b) const noexcept { return !(b < *this); }

    template<int LBITS>
    friend constexpr uVar<INTBITS+LBITS> operator*(const uVar<LBITS>& lhs, const uVar& rhs) noexcept {
        uVar<INTBITS+LBITS> out;
        static_assert(sizeof(radix2) >= 2*sizeof(radix));
        std::array<radix2, INTRADICES<INTBITS+LBITS>> wide {};
        for(size_t i = 0; i < lhs.v.size(); i++) {
            for(size_t j = 0; j < rhs.v.size(); j++) {
                wide[i+j] += static_cast<radix2>(lhs.v[i]) * static_cast<radix2>(rhs.v[j]);
            }
            assert(out.v.size() >= 1);
            for(size_t j = i; j < out.v.size()-1; j++) {
                wide[j+1] += wide[j] >> (sizeof(radix)* CHAR_BIT);
                wide[j] &=  static_cast<radix>(-1ULL);
            }
        }
        for(size_t i = 0; i < out.v.size(); i++) {
            out.v[i] = static_cast<radix>(wide[i]);
        }
        return out;
    }
    
    template<int LBITS>
    constexpr friend std::pair<uVar<LBITS>,uVar> divmod(const uVar<LBITS>& numerator, const uVar& denominator) noexcept {
        std::pair<uVar<LBITS>,uVar> out {{},{}};
        uVar<LBITS+INTBITS> quotient_shifted;
        uVar<LBITS+INTBITS> numerator_sub;
        std::copy(denominator.v.cbegin(), denominator.v.cend(), &quotient_shifted.v[numerator.v.size()]);
        std::copy(numerator.v.cbegin(), numerator.v.cend(), numerator_sub.v.begin());

        for (long i = numerator.v.size()*RADIXBITS; i >= 0; i--) {
            bool numerator_greater = numerator_sub >= quotient_shifted;
            auto set_bit = uint64_t(numerator_greater) << (i % RADIXBITS);
            out.first.v[i/RADIXBITS] |= set_bit;

            auto masked_quotient_buffer = quotient_shifted;
            for(auto& val : masked_quotient_buffer.v) {
                val *= numerator_greater;
            }
            numerator_sub -= masked_quotient_buffer;
            quotient_shifted >>= 1;
        }
        std::copy(numerator_sub.v.begin(), &numerator_sub.v[denominator.v.size()], out.second.v.begin());
        return out;
    }
    template<int LBITS>
    constexpr friend uVar<LBITS> operator/(const uVar<LBITS>& lhs, const uVar& rhs) noexcept {
        auto [divi, modi] = divmod(lhs, rhs);
        return divi;
    }
    template<int LBITS>
    constexpr friend uVar operator%(const uVar<LBITS>& lhs, const uVar& rhs) noexcept {
        auto [divi, modi] = divmod(lhs, rhs);
        return modi;
    }
    friend constexpr ct_u256 curve25519::REDC(ct_u512) noexcept;
    friend constexpr uVar<192> cha::REDCpoly(uVar<384>) noexcept;
};

constexpr ct_u256 operator "" _xl(const char* const str, std::size_t siz) {
    return std::string_view { str,siz };
}
constexpr ct_u512 operator "" _xll(const char* const str, std::size_t siz) {
    return std::string_view {str,siz};
}

} // namespace fbw

#endif // bignum_hpp
