//
//  galois_counter.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

// Abridged from
// https://github.com/michaeljclark/aes-gcm/blob/master/src/aes-gcm.c
// I added a GCM cipher because Chrome does not support CBC ciphers, which are slightly insecure


#include "galois_counter.hpp"
#include "../../../global.hpp"
#include "AES.hpp"
#include "../../TLS_enums.hpp"

#include <cstdlib>
#include <array>
#include <vector>
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>
#include <sys/types.h>



constexpr int AES_BLOCK_SIZE = 16;



namespace fbw::aes {


static inline uint32_t AES_GET_BE32(const uint8_t *a) {
    return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}

static inline void AES_PUT_BE32(uint8_t *a, uint32_t val) {
    a[0] = (val >> 24) & 0xff;
    a[1] = (val >> 16) & 0xff;
    a[2] = (val >> 8) & 0xff;
    a[3] = val & 0xff;
}

static inline void AES_PUT_BE64(uint8_t *a, uint64_t val)
{
    a[0] = val >> 56;
    a[1] = val >> 48;
    a[2] = val >> 40;
    a[3] = val >> 32;
    a[4] = val >> 24;
    a[5] = val >> 16;
    a[6] = val >> 8;
    a[7] = val & 0xff;
}

static void inc32(aes_block& block) {
    assert(block.size() >= 4);
    auto val = try_bigend_read(block, block.size() - 4, 4);
    val++;
    checked_bigend_write(val, block, block.size() - 4, 4);
    assert(val != uint32_t(-1));
}


static void xor_block(uint8_t *dst, const uint8_t *src) {
    for(int i = 0; i < 16; i ++) {
        *dst++ ^= *src++;
    }
}


static void shift_right_block(aes_block& v) {
    uint32_t val;
    val = AES_GET_BE32(v.data() + 12);
    val >>= 1;
    if (v[11] & 0x01) {
        val |= 0x80000000;
    }
    AES_PUT_BE32(v.data() + 12, val);

    val = AES_GET_BE32(v.data() + 8);
    val >>= 1;
    if (v[7] & 0x01) {
        val |= 0x80000000;
    }
    AES_PUT_BE32(v.data() + 8, val);

    val = AES_GET_BE32(v.data() + 4);
    val >>= 1;
    if (v[3] & 0x01)
        val |= 0x80000000;
    AES_PUT_BE32(v.data() + 4, val);

    val = AES_GET_BE32(v.data());
    val >>= 1;
    AES_PUT_BE32(v.data(), val);
}



static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
    aes_block v;
    int i, j;

    memset(z, 0, 16);
    memcpy(v.data(), y, 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & 1 << (7 - j)) {
                xor_block(z, v.data());
            }
            if (v[15] & 0x01) {
                shift_right_block(v);
                v[0] ^= 0xe1;
            } else {
                shift_right_block(v);
            }
        }
    }
}




// same as original
static void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y) {
    const uint8_t *xpos = x;
    uint8_t tmp[16];
    size_t m = xlen / 16;
    for (size_t i = 0; i < m; i++) {
        xor_block(y, xpos);
        xpos += 16;
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }
    if (x + xlen > xpos) {
        size_t last = x + xlen - xpos;
        memcpy(tmp, xpos, last);
        memset(tmp + last, 0, sizeof(tmp) - last);
        xor_block(y, tmp);
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }
}


static void aes_gctr(roundkey aesk, aes_block cb, const uint8_t *x, size_t xlen, uint8_t *y) {
    size_t last;

    if (xlen == 0)
        return;
    auto roundedx = (xlen &~15u);
    for (size_t i = 0; i < roundedx; i += AES_BLOCK_SIZE) {
        auto yy = aes_encrypt(cb, aesk);
        std::transform(yy.begin(), yy.end(), &x[i], yy.begin(), std::bit_xor<uint8_t>());
        memcpy(&y[i], &yy[0], AES_BLOCK_SIZE);
        inc32(cb);
    }

    last = xlen - roundedx;
    if (last) {

        auto tmp = aes_encrypt(cb, aesk);
        for (size_t i = 0; i < last; i++)
            y[i+roundedx] = x[i+roundedx] ^ tmp[i];
    }
}

static aes_block aes_gcm_prepare_j0(const ustring& iv, const aes_block& H) {
    uint8_t len_buf[16];
    
    aes_block J0 {};

    if (iv.size() == 12) {
        // Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96]
        std::copy(iv.begin(), iv.end(), J0.begin());
        J0[J0.size() - 1] = 0x01;
    } else {
        
        ghash(H.data(), iv.data(), iv.size(), J0.data());
        AES_PUT_BE64(len_buf, 0);
        AES_PUT_BE64(len_buf + 8, iv.size() * 8);
        ghash(H.data(), len_buf, sizeof(len_buf), J0.data());
    }
    return J0;
}


static void aes_gcm_gctr(roundkey aesk, const aes_block& J0, const uint8_t *in, size_t len,
                         uint8_t *out)
{
    if (len == 0) {
        return;
    }
    auto J0inc = J0;
    inc32(J0inc);
    aes_gctr(aesk, J0inc, in, len, out);
}


static ustring aes_gcm_ghash(const aes_block& H, const ustring& aad,
              const uint8_t *crypt, size_t crypt_len) {
    uint8_t len_buf[16];
    
    ustring S {};
    S.resize(16);
    ghash(H.data(), aad.data(), aad.size(), S.data());
    ghash(H.data(), crypt, crypt_len, S.data());
    AES_PUT_BE64(len_buf, aad.size() * 8);
    AES_PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H.data(), len_buf, sizeof(len_buf), S.data());
    return S;
}


// aes_gcm_ae - GCM-AE_K(IV, P, A)

std::pair<ustring,ustring> aes_gcm_ae(const roundkey& rk, const ustring& iv,
           const ustring& plain,
           const ustring& aad) {
    aes_block H {};
    ustring tag;

    H = aes_encrypt(H, rk);

    aes_block J0 = aes_gcm_prepare_j0(iv, H);
    ustring crypt;
    crypt.resize(plain.size());
    aes_gcm_gctr(rk, J0, plain.data(), plain.size(), crypt.data());
    
    auto S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    
    tag.resize(S.size());
    aes_gctr(rk, J0, S.data(), S.size(), tag.data());

    return {crypt, tag};
}



// aes_gcm_ad - GCM-AD_K(IV, C, A, T)

ustring aes_gcm_ad(roundkey rk, ustring iv,
           const ustring& crypt,
                   const ustring& aad, const ustring& tag) {
    
    aes_block H {};
    aes_block T {};
    ustring plain;
    
    H = aes_encrypt(H, rk);
    aes_block J0 = aes_gcm_prepare_j0(iv, H);
    plain.resize(crypt.size());
    aes_gcm_gctr(rk, J0, crypt.data(), crypt.size(), plain.data());
    ustring S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    aes_gctr(rk, J0, S.data(), S.size(), &T[0]);
    if(!std::equal(tag.begin(), tag.end(), T.begin())) [[unlikely]] {
        throw ssl_error("bad tag", AlertLevel::fatal, AlertDescription::bad_record_mac);
    }
    
    return plain;
}


[[maybe_unused]] ustring aes_gmac(roundkey key, const ustring& iv,
         const ustring& aad) {
    assert(false);
    auto [_, tag] = aes_gcm_ae(key, iv, {}, aad);
    return tag;
}




void AES_128_GCM_SHA256::set_key_material_12(ustring material) {

    std::vector<uint8_t> client_write_key;
    client_write_key.resize(16);
    std::vector<uint8_t> server_write_key;
    server_write_key.resize(16);
    
    client_implicit_write_IV.resize(4);
    server_implicit_write_IV.resize(4);
    
    auto it = material.begin();
    std::copy_n(it, client_write_key.size(), client_write_key.begin());
    it += client_write_key.size();
    std::copy_n(it, server_write_key.size(), server_write_key.begin());
    it += server_write_key.size();
    std::copy_n(it, client_implicit_write_IV.size(), client_implicit_write_IV.begin());
    it += client_implicit_write_IV.size();
    std::copy_n(it, server_implicit_write_IV.size(), server_implicit_write_IV.begin());
    it += server_implicit_write_IV.size();
    
    
    client_write_round_keys = aes_key_schedule(client_write_key);
    server_write_round_keys = aes_key_schedule(server_write_key);

}


tls_record AES_128_GCM_SHA256::encrypt(tls_record record) noexcept {

    
    ustring sequence_no;
    sequence_no.resize(8);
    
    checked_bigend_write(seqno_server, sequence_no, 0, 8);
    seqno_server++;

    uint16_t msglen = htons(record.m_contents.size());

    ustring additional_data = sequence_no;
    
    additional_data.append({static_cast<uint8_t>(record.get_type()), record.get_major_version(), record.get_minor_version()});
    
    additional_data.resize(13);
    std::memcpy(&additional_data[11], &msglen, 2);
    
    ustring iv = server_implicit_write_IV + sequence_no;

    auto [ciphertext, auth_tag] = aes_gcm_ae(server_write_round_keys, iv, record.m_contents, additional_data);
    
    assert(auth_tag.size() == 16);
    assert(sequence_no.size() == 8);
    
    record.m_contents = sequence_no + ciphertext + auth_tag;
    return record;
}

tls_record AES_128_GCM_SHA256::decrypt(tls_record record) {
    
    if(record.m_contents.size() < 24) [[unlikely]] {
        throw ssl_error("short record IV HMAC", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    
    ustring sequence;
    sequence.resize(8);
    checked_bigend_write(seqno_client, sequence, 0, 8);
    seqno_client++;

    ustring explicit_IV;
    explicit_IV.append({record.m_contents.begin(), record.m_contents.begin() + 8});
    ustring ciphertext;
    ciphertext.append({record.m_contents.begin() + 8, record.m_contents.end() - 16});
    ustring auth_tag;
    auth_tag.append({record.m_contents.end() - 16, record.m_contents.end()});
    
    assert(auth_tag.size() == 16);
    assert(explicit_IV.size() == 8);
    
    ustring additional_data;
    additional_data.append(sequence);
    additional_data.append({static_cast<uint8_t>(record.get_type()), record.get_major_version(), record.get_minor_version()});
    additional_data.resize(13);
    assert(record.m_contents.size() >= auth_tag.size() + explicit_IV.size());
    uint16_t msglen = htons(record.m_contents.size() - auth_tag.size() - explicit_IV.size());
    std::memcpy(&additional_data[11], &msglen, 2);

    auto iv = client_implicit_write_IV + explicit_IV;
    
    ustring plain = aes_gcm_ad(client_write_round_keys, iv, ciphertext, additional_data, auth_tag);
    record.m_contents = plain;
    
    if(record.m_contents.size() > TLS_RECORD_SIZE + DECRYPTED_TLS_RECORD_GIVE) [[unlikely]] {
        throw ssl_error("decrypted record too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    return record;
}

} // namespace fbw
