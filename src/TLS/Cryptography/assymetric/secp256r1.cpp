//
//  secp256r1.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 08/08/2021.
//


#include "bignum.hpp"
#include "secp256r1.hpp"
#include "../../../global.hpp"
#include "../../TLS_enums.hpp"

#include <cassert>
#include <array>
#include <string>
#include <sstream>
#include <iostream>
#include <print>


namespace fbw::secp256r1  {

using namespace std::literals;

struct affine_point256 {
    ct_u256 xcoord;
    ct_u256 ycoord;
    ct_u256 zcoord;
};


// Q is the group order of the curve and depends on P
// P has the property that all points are on the main group of order Q
// G is out of thin air
constexpr ct_u256 secp256r1_q = "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"_xl;
constexpr ct_u256 secp256r1_p = "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"_xl;
constexpr ct_u256 secp256r1_gx = "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"_xl;
constexpr ct_u256 secp256r1_gy = "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"_xl;
constexpr ct_u256 MagicP = "0xffffffff00000002000000000000000000000001000000000000000000000001"_xl;
constexpr ct_u256 MagicQ = "0x60d06633a9d6281c50fe77ecc588c6f648c944087d74d2e4ccd1c8aaee00bc4f"_xl;

// R mod P
constexpr ct_u256 R_P = "0xfffffffeffffffffffffffffffffffff000000000000000000000001"_xl;
constexpr ct_u256 RR_P = "0x4fffffffdfffffffffffffffefffffffbffffffff0000000000000003"_xl;
constexpr ct_u256 RR_Q = "0x66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea2"_xl;
constexpr ct_u256 aMontyP = "0xfffffffc00000004000000000000000000000003fffffffffffffffffffffffc"_xl;

// computes a such that T = a * R mod N
constexpr ct_u256 REDC(ct_u512 T) noexcept {
    ct_u256 m = ct_u256(ct_u256(T) * MagicP);
    ct_u512 t = ct_u512((ct_u768(T) + ct_u768(m*secp256r1_p))>>256);
    ct_u256 pri = secp256r1_p;
    const auto prime = ct_u512(pri);
    if(t >= prime) {
        return ct_u256(t - prime);
    } else {
        return ct_u256(t);
    }
}

constexpr ct_u256 REDCQ(ct_u512 T) noexcept {
    ct_u256 m = ct_u256(ct_u256(T) * MagicQ);
    ct_u512 t = ct_u512((ct_u768(T) + ct_u768(m*secp256r1_q))>>256);
    ct_u256 pri = secp256r1_q;
    const auto prime = ct_u512(pri);
    const auto diff = t - prime;
    auto mask = -(diff >> (sizeof(diff) * CHAR_BIT - 1)); // todo: don't use full 512 bit width, also slightly silly
    auto res = (diff & ~mask) | (t & mask);
    return ct_u256(res);
}



constexpr affine_point256 POINT_AT_INFINITY { secp256r1_p, secp256r1_p, "0x0"_xl};

ct_u256 add_mod(ct_u256 x, ct_u256 y , ct_u256 mod) noexcept {
    assert(x < mod);
    assert(y < mod);
    auto sum = x + y;
    if (sum < x or sum > mod) {
        sum -= mod;
    }
    return sum;
}

ct_u256 sub_mod(ct_u256 x, ct_u256 y, ct_u256 mod) noexcept {
    assert(x < mod);
    assert(y < mod);
    ct_u256 mask{};
    mask.v[0] = x > y;
    mask -= "0x1"_xl;
    return ((x - y) & ~mask) | (((mod - y) + x) & mask);
}

// computes a' such that a * a' = 1 mod P
constexpr ct_u256 modular_inverse(const ct_u256& a) noexcept {
    auto ladder = R_P;
    auto aR = REDC(a*RR_P);
    for(int i = sizeof(ct_u256)*CHAR_BIT-1; i >=0; i--) {
        auto prime_shift = (secp256r1_p-"0x2"_xl) >> i;
        if(prime_shift == "0x0"_xl) {
            continue;
        }
        auto reduced = REDC(ladder*ladder);
        auto next = REDC(aR*reduced);
        auto mask = (prime_shift&"0x1"_xl) - "0x1"_xl;
        ladder = (next & ~mask) | (reduced & mask);
    }
    return REDC(ct_u512(ladder));
}


constexpr ct_u256 invQ(const ct_u256& a) noexcept {
    auto th = "0x1"_xl;
    for (int i = 255; i >= 0; i--) {
        auto es = (secp256r1_q-"0x2"_xl)>>i;
        if(es == "0x0"_xl) {
            continue;
        }
        auto thh = th * th;
        auto t = thh % secp256r1_q;
        auto y = t * a;
        bool cond = es.v[0] != 0;
        ct_u512 mask{};
        mask.v[0] = cond;
        mask -= "0x1"_xll;
        auto oth = (y & mask) | (thh & ~mask);
        th = oth % secp256r1_q;
    }
    return th;
}

constexpr ct_u256 MontyinvQ(const ct_u256& a) noexcept {
    auto th = REDCQ(ct_u512(RR_Q));
    for (int i = 255; i >= 0; i--) {
        auto es = (secp256r1_q-"0x2"_xl)>>i;
        if(es == "0x0"_xl) {
            continue;
        }
        auto t = REDCQ(th * th);
        auto y = REDCQ(t * a);
        bool cond = (es.v[0] & 1) != 0;
        ct_u256 mask{};
        mask.v[0] = cond;
        mask -= "0x1"_xl;
        th = (y & ~mask) | (t & mask);
    }
    return th;
}

affine_point256 point_double(const affine_point256& P) noexcept;
// finds point R, on the line through P and Q
// The y coordinate is inferred from the base point.
affine_point256 point_add(const affine_point256& P, const affine_point256& Q) noexcept {
    if(P.ycoord == secp256r1_p) [[unlikely]] { // unreachable in practice therefore CT
        return Q;
    }
    if(Q.ycoord == secp256r1_p) [[unlikely]]  { // unreachable in practice therefore CT
        return P;
    }

    affine_point256 out;
    auto Z2Z2 = REDC(Q.zcoord * Q.zcoord);
    auto U1 = REDC(Z2Z2 * P.xcoord);
    auto Z1Z1 = REDC(P.zcoord * P.zcoord);
    auto U2 = REDC(Z1Z1 * Q.xcoord);
    auto Z23 = REDC(Q.zcoord * Z2Z2);
    auto S1 = REDC(P.ycoord * Z23);
    auto Z13 = REDC(P.zcoord * Z1Z1);
    auto S2 = REDC(Q.ycoord * Z13);
    if(U1 == U2) [[unlikely]] {
        if(S1 != S2) {
            std::println(std::cerr, "Point at infinity"); // unreachable in practice therefore CT
            return POINT_AT_INFINITY;
        } else {
            return point_double(P);
        }
    }
    
    auto H = sub_mod(U2, U1, secp256r1_p);
    auto Ra = sub_mod(S2, S1, secp256r1_p);
    auto RRa = REDC(Ra * Ra);
    auto HH = REDC(H * H);
    auto HHH = REDC(HH * H);
    auto U1HH = REDC(HH * U1);
    auto RRHHH = sub_mod(RRa, HHH, secp256r1_p);
    auto U1HH2 = add_mod(U1HH, U1HH, secp256r1_p);
    out.xcoord = sub_mod(RRHHH, U1HH2, secp256r1_p);
        
    auto S1HHH = REDC(S1 * HHH);
    auto U1HHX3 = sub_mod(U1HH, out.xcoord, secp256r1_p);
    auto RaU1HHx3 = REDC(Ra * U1HHX3);
    out.ycoord = sub_mod(RaU1HHx3, S1HHH, secp256r1_p);
    auto Z1Z2 = REDC(P.zcoord * Q.zcoord);
    out.zcoord = REDC(H * Z1Z2);
    return out;
}


// finds point R on the line tangent to point P on the curve
affine_point256 point_double(const affine_point256& P) noexcept {
    assert(P.ycoord <= secp256r1_p);
    
    if(P.ycoord == "0x0"_xl or P.ycoord == secp256r1_p) [[unlikely]] {
        std::println(std::cerr, "PD Point at Infinity");
        return POINT_AT_INFINITY;
    }
    affine_point256 out;
    auto YY = REDC(P.ycoord*P.ycoord);
    auto XYY = REDC(P.xcoord*YY);
    auto XYY2 = add_mod(XYY, XYY, secp256r1_p);
    auto S = add_mod(XYY2, XYY2, secp256r1_p);
    auto XX = REDC(P.xcoord*P.xcoord);
    auto XX2 = add_mod(XX,XX, secp256r1_p);
    auto XX3 = add_mod(XX,XX2,secp256r1_p);
    auto ZZ = REDC(P.zcoord * P.zcoord);
    auto ZZZZ = REDC(ZZ *ZZ);
    auto aZZZZ = REDC(aMontyP * ZZZZ);
    auto M = add_mod(XX3, aZZZZ, secp256r1_p);
    auto MM = REDC(M*M);
    auto S2 = add_mod(S,S,secp256r1_p);
    out.xcoord = sub_mod(MM, S2, secp256r1_p);
    auto SX3 = sub_mod(S, out.xcoord, secp256r1_p);
    auto MSX3 = REDC(M*SX3);
    auto YYYY = REDC(YY*YY);
    auto YYYY2 = add_mod(YYYY,YYYY, secp256r1_p);
    auto YYYY4 = add_mod(YYYY2,YYYY2, secp256r1_p);
    auto YYYY8 = add_mod(YYYY4,YYYY4, secp256r1_p);
    out.ycoord = sub_mod(MSX3, YYYY8, secp256r1_p);
    auto YZ = REDC(P.ycoord * P.zcoord);
    out.zcoord = add_mod(YZ, YZ, secp256r1_p);
    return out;
}

affine_point256 point_multiply_affine(const ct_u256& secret, const ct_u256& x_coord, const ct_u256& y_coord) noexcept {
    assert(secret <= secp256r1_q);
    assert(secret != "0x0"_xl);

    
    affine_point256 out {"0x0"_xl,"0x0"_xl,"0x0"_xl};

    affine_point256 P;
    P.xcoord = REDC(x_coord*RR_P);
    P.ycoord = REDC(y_coord*RR_P);
    P.zcoord = R_P;

    int init = 0;
    
    for(int i = 0; i < 256; i ++) {
        auto b = "0x1"_xl << i;
        if((b & secret) != "0x0"_xl) { // todo: CT
            ct_u256 mask;
            mask.v[0] = (init == 0);
            mask -= "0x1"_xl;
            auto sum = point_add(P, out);
            out.xcoord = (P.xcoord & ~mask) | (sum.xcoord & mask);
            out.ycoord = (P.ycoord & ~mask) | (sum.ycoord & mask);
            out.zcoord = (P.zcoord & ~mask) | (sum.zcoord & mask);
            init |= 1;
        }
        P = point_double(P);
    }
    return out;
}

std::pair<ct_u256,ct_u256> project(affine_point256 P) noexcept {
    if(P.xcoord == POINT_AT_INFINITY.xcoord) [[unlikely]] { 
        return { "0x0"_xl, "0x0"_xl };
    }
    auto zz = REDC(P.zcoord * P.zcoord);
    auto zzz = REDC(P.zcoord * zz);
    ct_u256 invzz = modular_inverse(REDC(ct_u512(zz)));
    ct_u256 invzzz = modular_inverse(REDC(ct_u512(zzz)));
    auto v = REDC(P.xcoord * invzz);
    auto w = REDC(P.ycoord * invzzz);
    return {v, w };
}

// computes P + P + ... + P (N times) and returns the x coordinate.
// x_coord is the x coordinate of P, and N is some secret number.
// note that we assume that the y coordinate of P is the same as G's.
std::pair<ct_u256,ct_u256> point_multiply(ct_u256 secret, const ct_u256& x_coord, const ct_u256& y_coord) noexcept {
    if(secret > secp256r1_q) [[unlikely]] {
        secret = secret - secp256r1_q;
    }
    affine_point256 out = point_multiply_affine(secret, x_coord, y_coord);
    return project(out);
}

std::array<uint8_t, 32> multiply(const std::array<uint8_t, 32>& private_key, const std::array<uint8_t, 65>& peer_public_key) noexcept {
    // convert point to x and y coords
    std::array<uint8_t, 32> x_coord {};
    std::array<uint8_t, 32> y_coord {};
    std::copy(peer_public_key.begin() + 1, peer_public_key.begin() + 33, x_coord.begin());
    std::copy(peer_public_key.begin() + 33, peer_public_key.end(), y_coord.begin());

    auto [ x, y ] = point_multiply(private_key, x_coord, y_coord);
    const auto xser = x.serialise();
    std::array<uint8_t, 32> out;
    std::copy(xser.cbegin(), xser.cend(), out.begin());
    return out;
}

std::array<unsigned char,65> get_public_key(std::array<uint8_t,32> private_key) noexcept {

    auto [x, y] = point_multiply(ct_u256(private_key), secp256r1_gx, secp256r1_gy);
    std::array<unsigned char,65> out;
    out[0] = 0x04;
    
    auto xs = x.serialise();
    auto ys = y.serialise();
    std::copy(xs.cbegin(), xs.cend(), &out[1]);
    std::copy(ys.cbegin(), ys.cend(), &out[33]);
    return out;
}

struct ECDSA_signature {
    ct_u256 r;
    ct_u256 s;
};

// unoptimised
// treat as a debug tool
bool verify_signature(const ct_u256& h,
                      const ct_u256& r,
                      const ct_u256& s,
                      const ct_u256& pub_x,
                      const ct_u256& pub_y) {
    if(r == "0x0"_xl or s == "0x0"_xl) {
        return false;
    }
    if(r >= secp256r1_q or s >= secp256r1_q) {
        return false;
    }
    auto s1 = invQ(s);
    // note P, Q, R are in Montgomery Jacobian coordinates
    auto P = point_multiply_affine( (h * s1) % secp256r1_q, secp256r1_gx, secp256r1_gy);
    auto Q = point_multiply_affine( (r * s1) % secp256r1_q, pub_x, pub_y);
    auto R = point_add(P, Q);
    auto [x,y] = project(R); // converts back to cartesian coordinates
    return (x == r);
}




ECDSA_signature ECDSA_impl(const ct_u256& k_random, const ct_u256& digest, const ct_u256& private_key) {
    if(k_random == "0x0"_xl) [[unlikely]] {
        throw ssl_error("bad random", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    
    auto [x, y] = point_multiply(k_random, secp256r1_gx, secp256r1_gy);
    if(x >= secp256r1_q) [[unlikely]] {
        x -= secp256r1_q;
    }
    
    auto r = x;
    if(r == "0x0"_xl) [[unlikely]] {
        throw ssl_error("bad random", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    
    const auto k_randomMonty = REDCQ(RR_Q*k_random);
    const auto vvv = MontyinvQ(k_randomMonty);
    const auto digestMonty = REDCQ(RR_Q*digest);
    const auto rMonty = REDCQ(RR_Q*r);
    const auto privMonty = REDCQ(RR_Q*private_key);
    const auto rpMonty = REDCQ(rMonty*privMonty);
    const auto drpMonty = add_mod(rpMonty, digestMonty , secp256r1_q);
    const auto sMonty = REDCQ(vvv*drpMonty);
    const auto s = REDCQ(ct_u512(sMonty));
    
    if(s == "0x0"_xl) [[unlikely]] {
        throw ssl_error("bad random", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    //auto [pubx, puby] = point_multiply(ct_u256(private_key), secp256r1_gx, secp256r1_gy);
    //assert(verify_signature(digest,r, s, pubx, puby));
    
    return {r, s};
}

ustring raw_ECDSA(std::array<uint8_t,32> k_random,
                     std::array<uint8_t,32> digest,
                     std::array<uint8_t,32> private_key) {
    auto signature = ECDSA_impl(std::move(k_random), std::move(digest), std::move(private_key));
    auto r = signature.r.serialise();
    auto s = signature.s.serialise();
    ustring out;
    out.insert(out.end(), r.begin(), r.end());
    out.insert(out.end(), s.begin(), s.end());
    return out;
}

ustring DER_ECDSA(
                     std::array<uint8_t,32> k_random,
                     std::array<uint8_t,32> digest,
                     std::array<uint8_t,32> private_key) {
    
    auto signature = ECDSA_impl(std::move(k_random), std::move(digest), std::move(private_key));
    auto r = signature.r.serialise();
    auto s = signature.s.serialise();
    

    ustring out;
    out.insert(out.end(), {0x30,0x00, 0x02});
    
    if(r[0]&0x80) {
        out.insert(out.end(), {0x21,0x00});
    } else {
        out.insert(out.end(),{0x20});
    }
    out.insert(out.end(),r.cbegin(),r.cend());
    out.insert(out.end(), {0x02});
    if(s[0]&0x80) {
        out.insert(out.end(), {0x21,0x00});
    } else {
        out.insert(out.end(), {0x20});
    }
    out.insert(out.end(), s.cbegin(),s.cend());
    assert(out.size() >= 2);
    assert(out.size() < 256);
    out[1] = static_cast<uint8_t>(out.size()-2);
    return out;
    
}


} // namespace fbw::secp256r1

