//
//  chacha20poly1305.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/02/2022.
//

#include "chacha20poly1305.hpp"

#include "../../../global.hpp"
#include "../one_way/keccak.hpp"
#include "../assymetric/bignum.hpp"

#include "../one_way/sha2.hpp"

#include <arpa/inet.h>
#include <sys/types.h>
#include <cstring>
#include <algorithm>
#include <array>

namespace fbw::cha {



constexpr uint32_t ROT32(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = ROT32(d, 16);
    c += d; b ^= c; b = ROT32(b, 12);
    a += b; d ^= a; d = ROT32(d, 8);
    c += d; b ^= c; b = ROT32(b, 7);
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

std::array<uint8_t, 64> chacha20_inner(const std::array<uint32_t, 16>& state_orig, uint32_t block_count) {
    auto state = state_orig;
    state[12] = block_count;
    
    for (int i = 0; i < 10; ++i) {
        chacha_quarter_round(state[0], state[4], state[8], state[12]);
        chacha_quarter_round(state[1], state[5], state[9], state[13]);
        chacha_quarter_round(state[2], state[6], state[10], state[14]);
        chacha_quarter_round(state[3], state[7], state[11], state[15]);

        chacha_quarter_round(state[0], state[5], state[10], state[15]);
        chacha_quarter_round(state[1], state[6], state[11], state[12]);
        chacha_quarter_round(state[2], state[7], state[8], state[13]);
        chacha_quarter_round(state[3], state[4], state[9], state[14]);
    }
    std::array<uint8_t, 64> out;
    state[12] += block_count;
    for(int i = 0; i < 16; i++) {
        uint32_t statei = state[i] + state_orig[i];
        write32_bigend(statei, &out[i*4]);
    }
    return out;
}

std::array<uint32_t, 16> chacha20_state(const std::array<uint8_t, KEY_SIZE>& key, const std::array<uint8_t, IV_SIZE>& number_once) {
    std::array<uint32_t, 16> state {0};
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    for(int i = 0; i < 8; i++) {
        state[i+4] = asval_bigend(&key[i*4]);
    }
    
    for(int i = 0; i < 3; i++) {
        state[i+13] = asval_bigend(&number_once[i*4]);
    }
    return state;
}

std::array<uint8_t, 64> chacha20(const std::array<uint8_t, KEY_SIZE>& key, const std::array<uint8_t, IV_SIZE>& number_once, uint32_t block_count) {
    auto state = chacha20_state(key, number_once);
    return chacha20_inner(state, block_count);
}

ustring chacha20_xorcrypt(   const std::array<uint8_t, KEY_SIZE>& key,
                            uint32_t blockid,
                            const std::array<uint8_t, IV_SIZE>& number_once,
                            const ustring& message) {
    
    ustring out;
    out.resize(message.size());

    auto state = chacha20_state(key, number_once);
    
    size_t k = 0;
    // massive parallelism here?
    for(size_t i = 0; i < (message.size()+63) /64; i++) {
        std::array<uint8_t, 64> ou = chacha20_inner(state, uint32_t(i)+blockid);
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
    if(a > prime130_5) [[unlikely]] {
        return a - prime130_5;
    }
    return a;
}


u192 add_mod(u192 x, u192 y , u192 mod) noexcept {
    auto sum = x + y;
    assert(sum >= x);
    if (sum > mod) { // todo constant time
        sum -= mod;
    }
    return sum;
}

ct_u256 sub_mod(ct_u256 x, ct_u256 y, ct_u256 mod) noexcept {
    if(x > y) { // todo: constant time
        return x - y;
    } else {
        return (mod - y) + x;
    }
}


std::array<uint8_t, TAG_SIZE> poly1305_mac(const ustring& message, const std::array<uint8_t, KEY_SIZE>& key) {
    
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
        
        std::copy_n(&message[i], siz, inp.rbegin());
        inp[23-siz] = 1;

        accumulator = add_mod(accumulator, REDCpoly(u192(inp) * poly_RRP), prime130_5);
        accumulator = REDCpoly(accumulator * rMonty);
        
         
    }
    accumulator = REDCpoly(u384(accumulator));
    
    accumulator += s;
    auto out = accumulator.serialise();
    std::array<uint8_t, TAG_SIZE> out_str;
    std::copy_n(out.rbegin(), TAG_SIZE, out_str.begin());
    return out_str;
}

std::array<uint8_t, KEY_SIZE> poly1305_key_gen(const std::array<uint8_t, KEY_SIZE>& key, const std::array<uint8_t, IV_SIZE>& number_once) {
    std::array<uint8_t, 64> bl = chacha20(key, number_once, 0);
    std::array<uint8_t, KEY_SIZE> out;
    std::copy_n(bl.begin(), KEY_SIZE, out.begin());
    return out;
}



// encrypt or decrypt
std::pair<ustring, std::array<uint8_t, TAG_SIZE>>
chacha20_aead_crypt(ustring aad, std::array<uint8_t, KEY_SIZE> key, std::array<uint8_t, IV_SIZE> number_once, ustring text, bool do_encrypt) {
    
    auto otk = poly1305_key_gen(key, number_once);
    auto xortext = chacha20_xorcrypt(key, 1, number_once, text);

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

void ChaCha20_Poly1305_tls13::set_server_traffic_key(const ustring& traffic_key) {
    auto key = hkdf_expand_label(sha256(), traffic_key, "key", std::string(""), KEY_SIZE);
    auto iv = hkdf_expand_label(sha256(), traffic_key, "iv", std::string(""), IV_SIZE);
    std::copy(key.begin(), key.end(), ctx.server_write_key.begin());
    std::copy(iv.begin(), iv.end(), ctx.server_implicit_write_IV.begin());
    ctx.seqno_server = 0;
}

void ChaCha20_Poly1305_tls13::set_client_traffic_key(const ustring& traffic_key) {
    auto key = hkdf_expand_label(sha256(), traffic_key, "key", std::string(""), KEY_SIZE);
    auto iv = hkdf_expand_label(sha256(), traffic_key, "iv", std::string(""), IV_SIZE);
    std::copy(key.begin(), key.end(), ctx.client_write_key.begin());
    std::copy(iv.begin(), iv.end(), ctx.client_implicit_write_IV.begin());
    ctx.seqno_client = 0;
}

void ChaCha20_Poly1305_tls12::set_key_material_12(ustring material) {
    
    auto it = material.begin();
    std::copy_n(it, ctx.client_write_key.size(), ctx.client_write_key.begin());
    it += ctx.client_write_key.size();
    std::copy_n(it, ctx.server_write_key.size(), ctx.server_write_key.begin());
    it += ctx.server_write_key.size();
    std::copy_n(it, ctx.client_implicit_write_IV.size(), ctx.client_implicit_write_IV.begin());
    it += ctx.client_implicit_write_IV.size();
    std::copy_n(it, ctx.server_implicit_write_IV.size(), ctx.server_implicit_write_IV.begin());
    it += ctx.server_implicit_write_IV.size();
}

ustring make_additional_12(tls_record& record, uint64_t sequence_no, size_t tag_size) {
    assert(record.m_contents.size() >= tag_size);
    uint16_t msglen = htons(record.m_contents.size() - tag_size);
    ustring additional_data(8, 0);
    checked_bigend_write(sequence_no, additional_data, 0, 8);
    additional_data.append({static_cast<uint8_t>(record.get_type()), record.get_major_version(), record.get_minor_version()});
    additional_data.resize(13);
    std::memcpy(&additional_data[11], &msglen, 2);
    return additional_data;
}

std::array<uint8_t, IV_SIZE> make_number_once(std::array<uint8_t, IV_SIZE> IV, uint64_t seq) {
    std::array<uint8_t,sizeof(uint64_t)> sequence_no;
    checked_bigend_write(seq, sequence_no, 0, sizeof(uint64_t));
    for(size_t i = 0; i < sizeof(uint64_t); i ++) {
        IV[i+IV_SIZE-sizeof(uint64_t)] ^= sequence_no[i];
    }
    return IV;
}

ustring ChaCha20_Poly1305_ctx::encrypt(ustring plaintext, ustring additional_data) {
    auto number_once = make_number_once(server_implicit_write_IV, seqno_server);
    seqno_server++;
    auto [ciphertext, tag] = chacha20_aead_crypt(additional_data, server_write_key, number_once, std::move(plaintext), true);
    ciphertext.append(tag.begin(), tag.end());
    return ciphertext;
}

ustring ChaCha20_Poly1305_ctx::decrypt(ustring ciphertext, ustring additional_data) {
    assert(ciphertext.size() >= TAG_SIZE);
    std::array<uint8_t, TAG_SIZE> tag;
    std::copy(ciphertext.end() - TAG_SIZE, ciphertext.end(), tag.begin());
    ciphertext.resize(ciphertext.size() - TAG_SIZE);
    auto number_once = make_number_once(client_implicit_write_IV, seqno_client);
    seqno_client++;
    auto [plaintext, tag_recalc] = chacha20_aead_crypt(additional_data, client_write_key, number_once, ciphertext, false);
    if(tag != tag_recalc) [[unlikely]] {
        throw ssl_error("bad MAC", AlertLevel::fatal, AlertDescription::bad_record_mac);
    }
    if(plaintext.size() > TLS_RECORD_SIZE + DECRYPTED_TLS_RECORD_GIVE) [[unlikely]] {
        throw ssl_error("decrypted record too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    return plaintext;
}

tls_record ChaCha20_Poly1305_tls13::protect(tls_record record) noexcept {
    record = wrap13(std::move(record));
    ustring additional_data = make_additional_13(record.m_contents, TAG_SIZE);
    record.m_contents = ctx.encrypt(std::move(record.m_contents), additional_data);
    return record;
}

tls_record ChaCha20_Poly1305_tls12::protect(tls_record record) noexcept {
    ustring additional_data = make_additional_12(record, ctx.seqno_server, 0);
    record.m_contents = ctx.encrypt(std::move(record.m_contents), additional_data);
    return record;
}

tls_record ChaCha20_Poly1305_tls13::deprotect(tls_record record) {
    if(record.m_contents.size() < TAG_SIZE) {
        throw ssl_error("short record Poly1305", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    ustring additional_data = make_additional_13(record.m_contents, 0);
    record.m_contents = ctx.decrypt(std::move(record.m_contents), additional_data);
    record = unwrap13(std::move(record));
    return record;
}

tls_record ChaCha20_Poly1305_tls12::deprotect(tls_record record) {
    if(record.m_contents.size() < TAG_SIZE) {
        throw ssl_error("short record Poly1305", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    ustring additional_data = make_additional_12(record, ctx.seqno_client, TAG_SIZE);
    record.m_contents = ctx.decrypt(record.m_contents, additional_data);
    return record;
}

bool ChaCha20_Poly1305_tls13::do_key_reset() {
    return ctx.seqno_client > (1ull << 48) or ctx.seqno_server > (1ull << 48);
}


} // namespace fbw::cha

