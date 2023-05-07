//
//  chacha20poly1305.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/02/2022.
//

#include "chacha20poly1305.hpp"

#include "global.hpp"
#include "keccak.hpp"
#include "bignum.hpp"

#include <arpa/inet.h>
#include <sys/types.h>
#include <cstring>
#include <algorithm>
#include <array>

namespace fbw::cha {

constexpr uint32_t ROT32(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

void chacha_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROT32(*d, 16);
    *c += *d; *b ^= *c; *b = ROT32(*b, 12);
    *a += *b; *d ^= *a; *d = ROT32(*d, 8);
    *c += *d; *b ^= *c; *b = ROT32(*b, 7);
}


inline void write32_bigend(uint32_t x, uint8_t* s) noexcept {
    for(short i = 0; i < 4; i++) {
        s[i] = static_cast<uint8_t>(x) & 0xffU;
        x>>=8;
    }
}

[[nodiscard]] inline uint32_t asval_bigend(uint8_t const* s) {
    uint32_t len = 0;
    for(int i = 3; i >= 0; i--) {
        len <<= 8;
        len |= s[i];
    }
    return len;
}

std::array<uint8_t, 64> chacha20(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 12>& nonce, uint32_t block_count) {
    
    std::array<uint32_t, 16> state {0};
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    for(int i = 0; i < 8; i++) {
        state[i+4] = asval_bigend(&key[i*4]);
    }
    
    state[12] = block_count;
    for(int i = 0; i < 3; i++) {
        state[i+13] = asval_bigend(&nonce[i*4]);
    }

    
    const auto state_orig = state;
    for(int j = 0; j < 10; j++) {
        for(int i = 0; i < 4; i++) {
            chacha_quarter_round(&state[i], &state[i+4], &state[i+8], &state[i+12]);
        }
        for(int i = 0; i < 4; i++) {
            chacha_quarter_round(&state[i], &state[4 + ((i+1) % 4)], &state[8 + ((i+2) % 4)], &state[12 + ((i+3) % 4)]);
        }
    }
    std::array<uint8_t, 64> out;
    for(int i = 0; i < 16; i++) {
        uint32_t statei = state[i] + state_orig[i];
        write32_bigend(statei, &out[i*4]);
    }
    return out;
}

ustring chacha20_xorcrypt(   const std::array<uint8_t, 32>& key,
                            uint32_t blockid,
                            const std::array<uint8_t, 12>& nonce,
                            const ustring& message) {
    
    ustring out;
    out.resize(message.size());
    
    size_t k = 0;
    for(size_t i = 0; i < (message.size()+63) /64; i++) {
        std::array<uint8_t, 64> ou = chacha20(key, nonce, uint32_t(i)+blockid);
        for(size_t j = 0;  j < 64 and k < message.size(); j++, k++) {
            out[k] = ou[j];
        }
    }
    for(size_t i = 0; i < message.size(); i++) {
        out[i] ^= message[i];
    }
    return out;
}

void poly1305_clamp(uint8_t* r) {
     r[3] &= 15;
     r[7] &= 15;
     r[11] &= 15;
     r[15] &= 15;
     r[4] &= 252;
     r[8] &= 252;
     r[12] &= 252;
}

using u192 = uVar<192>;
using u384 = uVar<384>;
constexpr u192 prime130_5 ("0x3fffffffffffffffffffffffffffffffb");
constexpr u192 magic_poly("0xa3d70a3d70a3d70cccccccccccccccccccccccccccccccd");
constexpr u192 poly_RRP ("0x190000000000000000000000000000000");

// program bottlenecks here so using the intrusive REDC form
constexpr u192 REDCpoly(u384 aR) noexcept {
    using radix = u192::radix;
    using radix2 = u192::radix2;
    u192 a;
    for(size_t i = 0; i < a.v.size(); i++) {
        radix2 carry = 0;
        radix2 congruent_multiplier = static_cast<radix>(aR.v[i]*magic_poly.v[0]);
        
        for(size_t j = 0; j < a.v.size(); j++) {
            radix2 x = static_cast<radix2>(aR.v[i+j]) + congruent_multiplier * static_cast<radix2>(prime130_5.v[j]) + carry;
            aR.v[i+j] = static_cast<radix>(x);
            carry = x >> ct_u256::RADIXBITS;
        }
        assert(aR.v.size() >= i);
        for(size_t j = a.v.size(); j < aR.v.size() - i; j++){
            radix2 x = static_cast<radix2>(aR.v[i+j]) + carry;
            aR.v[i+j] = static_cast<radix>(x);
            carry = x >> ct_u256::RADIXBITS;
        }
    }
    for(size_t i = 0; i < prime130_5.v.size(); i++) {
        a.v[i] = aR.v[i + prime130_5.v.size()];
    }
    if(a > prime130_5) {
        return a - prime130_5;
    } else {
        return a;
    }
}


u192 add_mod(u192 x, u192 y , u192 mod) noexcept {
    auto sum = x + y;
    assert(sum >= x);
    if (sum > mod) {
        sum -= mod;
    }
    return sum;
}

ct_u256 sub_mod(ct_u256 x, ct_u256 y, ct_u256 mod) noexcept {
    if(x > y) {
        return x - y;
    } else {
        return (mod - y) + x;
    }
}


std::array<uint8_t, 16> poly1305_mac(const ustring& message, const std::array<uint8_t, 32>& key) {
    
    std::array<uint8_t, 24> r_bytes {0};
    std::copy_n(&key[0], 16, r_bytes.begin());
    poly1305_clamp(&r_bytes[0]);
    std::reverse(r_bytes.begin(), r_bytes.end());
    
    std::array<uint8_t, 24> s_bytes {0};
    std::copy_n(&key[16], 16, s_bytes.rbegin());

    u192 accumulator ("0x0");
    u192 r(r_bytes);
    u192 s(s_bytes);
    
    auto rMonty = REDCpoly(r * poly_RRP);

    for(size_t i = 0; i < ((message.size()+15)/16)*16; i+=16) {
        std::array<uint8_t,24> inp {0};
        assert(message.size() > i);
        
        auto siz = std::min(static_cast<size_t>(16), message.size() - i);
        
        std::copy_n(&message[i], siz, inp.begin());
        inp[siz] = 1;
        std::reverse(inp.begin(), inp.end());

        accumulator = add_mod(accumulator, REDCpoly(u192(inp) * poly_RRP), prime130_5);
        accumulator = REDCpoly(accumulator * rMonty);
        
         
    }
    accumulator = REDCpoly(u384(accumulator));
    
    accumulator += s;
    auto out = accumulator.serialise();
    std::array<uint8_t, 16> out_str;
    std::copy_n(out.rbegin(), 16, out_str.begin());
    return out_str;
}

std::array<uint8_t, 32> poly1305_key_gen(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 12>& nonce) {
    std::array<uint8_t, 64> bl = chacha20(key, nonce, 0);
    std::array<uint8_t, 32> out;
    std::copy_n(bl.begin(), 32, out.begin());
    return out;
}




std::pair<ustring, std::array<uint8_t, 16>>
chacha20_aead_crypt(ustring aad, std::array<uint8_t, 32> key, std::array<uint8_t, 12> nonce, ustring text, bool do_encrypt) {
    
    auto otk = poly1305_key_gen(key, nonce);
    auto xortext = chacha20_xorcrypt(key, 1, nonce, text);

    std::array<uint8_t, 8> aad_size {};
    std::array<uint8_t, 8> cip_size {};
    
    for(int i = 0; i < 4; i++) {
        aad_size[i] = (aad.size() >> (8*i)) & 0xff;
        cip_size[i] = (xortext.size() >> (8*i)) & 0xff;
    }
    
    auto & ciphertext = do_encrypt ? xortext : text;

    size_t padaad = ((aad.size()+15)/16)*16 - aad.size();
    size_t padcipher = ((ciphertext.size()+15)/16)*16 - xortext.size();
    
    ustring mac_data;
    mac_data.append(aad);
    mac_data.append(padaad, 0);
    mac_data.append(ciphertext);
    mac_data.append(padcipher, 0);
    mac_data.append(aad_size.begin(), aad_size.end());
    mac_data.append(cip_size.begin(), cip_size.end());
    

    auto tag = poly1305_mac(mac_data, otk);
    return {xortext, tag};
}




void ChaCha20_Poly1305::set_key_material(ustring material) {
    
    auto it = material.begin();
    std::copy_n(it, client_write_key.size(), client_write_key.begin());
    it += client_write_key.size();
    std::copy_n(it, server_write_key.size(), server_write_key.begin());
    it += server_write_key.size();
    std::copy_n(it, client_implicit_write_IV.size(), client_implicit_write_IV.begin());
    it += client_implicit_write_IV.size();
    std::copy_n(it, server_implicit_write_IV.size(), server_implicit_write_IV.begin());
    it += server_implicit_write_IV.size();
}

ustring make_additional(tls_record& record, std::array<uint8_t,8>& sequence_no, size_t tag_size) {
    assert(record.m_contents.size() >= tag_size);
    uint16_t msglen = htons(record.m_contents.size() - tag_size);
    ustring additional_data;
    additional_data.append(sequence_no.begin(), sequence_no.end());
    additional_data.append({record.get_type(), record.get_major_version(), record.get_minor_version()});
    additional_data.resize(13);
    std::memcpy(&additional_data[11], &msglen, 2);
    return additional_data;
}

tls_record ChaCha20_Poly1305::encrypt(tls_record record) noexcept {
    std::array<uint8_t,8> sequence_no;
    checked_bigend_write(seqno_server, sequence_no, 0, 8);
    seqno_server++;
    ustring additional_data = make_additional(record, sequence_no, 0);
    std::array<uint8_t, 12> nonce = server_implicit_write_IV;
    for(int i = 0; i < 8; i ++) {
        nonce[i+4] ^= sequence_no[i];
    }
    auto [ciphertext, tag] = chacha20_aead_crypt(additional_data, server_write_key, nonce, record.m_contents, true);
    record.m_contents = ciphertext;
    record.m_contents.append(tag.begin(), tag.end());
    return record;
}

tls_record ChaCha20_Poly1305::decrypt(tls_record record) {
    if(record.m_contents.size() < 16) {
        throw ssl_error("short record Poly1305", AlertLevel::fatal, AlertDescription::decrypt_error);
    }

    std::array<uint8_t, 8> sequence_no {};
    checked_bigend_write(seqno_client, sequence_no, 0, 8);
    seqno_client++;

    ustring additional_data = make_additional(record, sequence_no, 16);

    ustring ciphertext;
    ciphertext.append(record.m_contents.begin(), record.m_contents.end()-16);
    
    std::array<uint8_t, 16> tag;
    assert(std::distance(record.m_contents.begin(), record.m_contents.end()) >= 16);
    std::copy(record.m_contents.end()-16, record.m_contents.end(), tag.begin());
    
    std::array<uint8_t,12> nonce = client_implicit_write_IV;
    for(int i = 0; i < 8; i++) {
        nonce[i+4] ^= sequence_no[i];
    }
    
    auto [plaintext, tag_recalc] = chacha20_aead_crypt(additional_data, client_write_key, nonce, ciphertext, false);

    if(tag != tag_recalc) {
        throw ssl_error("bad MAC", AlertLevel::fatal, AlertDescription::bad_record_mac);
    }
    record.m_contents = plaintext;
    return record;
}


    
} // namespace fbw::cha

