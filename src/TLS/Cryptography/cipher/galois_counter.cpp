//
//  galois_counter.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#include "galois_counter.hpp"
#include "../../../global.hpp"
#include "AES.hpp"
#include "../../TLS_enums.hpp"
#include "../one_way/sha2.hpp"

#include <algorithm>
#include <cstdlib>
#include <array>
#include <utility>
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
    if ((v[11] & 0x01) != 0) {
        val |= 0x80000000;
    }
    AES_PUT_BE32(v.data() + 12, val);

    val = AES_GET_BE32(v.data() + 8);
    val >>= 1;
    if ((v[7] & 0x01) != 0) {
        val |= 0x80000000;
    }
    AES_PUT_BE32(v.data() + 8, val);

    val = AES_GET_BE32(v.data() + 4);
    val >>= 1;
    if ((v[3] & 0x01) != 0) {
        val |= 0x80000000;
}
    AES_PUT_BE32(v.data() + 4, val);

    val = AES_GET_BE32(v.data());
    val >>= 1;
    AES_PUT_BE32(v.data(), val);
}



static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
    aes_block v;
    int i;
    int j;

    memset(z, 0, 16);
    memcpy(v.data(), y, 16);

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if ((x[i] & 1 << (7 - j)) != 0) {
                xor_block(z, v.data());
            }
            if ((v[15] & 0x01) != 0) {
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
    size_t const m = xlen / 16;
    for (size_t i = 0; i < m; i++) {
        xor_block(y, xpos);
        xpos += 16;
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }
    if (x + xlen > xpos) {
        size_t const last = x + xlen - xpos;
        memcpy(tmp, xpos, last);
        memset(tmp + last, 0, sizeof(tmp) - last);
        xor_block(y, tmp);
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }
}


static void aes_gctr(const roundkey& aesk, aes_block cb, const uint8_t *x, size_t xlen, uint8_t *y) {
    size_t last;

    if (xlen == 0) {
        return;
}
    auto roundedx = (xlen &~15U);
    for (size_t i = 0; i < roundedx; i += AES_BLOCK_SIZE) {
        auto yy = aes_encrypt(cb, aesk);
        std::transform(yy.begin(), yy.end(), &x[i], yy.begin(), std::bit_xor<uint8_t>());
        memcpy(&y[i], yy.data(), AES_BLOCK_SIZE);
        inc32(cb);
    }

    last = xlen - roundedx;
    if (last != 0U) {

        auto tmp = aes_encrypt(cb, aesk);
        for (size_t i = 0; i < last; i++) {
            y[i+roundedx] = x[i+roundedx] ^ tmp[i];
}
    }
}

static aes_block aes_gcm_prepare_j0(const std::vector<uint8_t>& iv, const aes_block& H) {
    uint8_t len_buf[16];
    
    aes_block J0 {};

    if (iv.size() == 12) {
        // Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96]
        std::ranges::copy(iv, J0.begin());
        J0[J0.size() - 1] = 0x01;
    } else {
        
        ghash(H.data(), iv.data(), iv.size(), J0.data());
        AES_PUT_BE64(len_buf, 0);
        AES_PUT_BE64(len_buf + 8, iv.size() * 8);
        ghash(H.data(), len_buf, sizeof(len_buf), J0.data());
    }
    return J0;
}


static void aes_gcm_gctr(const roundkey& aesk, const aes_block& J0, const uint8_t *in, size_t len,
                         uint8_t *out)
{
    if (len == 0) {
        return;
    }
    auto J0inc = J0;
    inc32(J0inc);
    aes_gctr(std::move(aesk), J0inc, in, len, out);
}


static std::vector<uint8_t> aes_gcm_ghash(const aes_block& H, const std::vector<uint8_t>& aad,
              const uint8_t *crypt, size_t crypt_len) {
    uint8_t len_buf[16];
    
    std::vector<uint8_t> S {};
    S.resize(16);
    ghash(H.data(), aad.data(), aad.size(), S.data());
    ghash(H.data(), crypt, crypt_len, S.data());
    AES_PUT_BE64(len_buf, aad.size() * 8);
    AES_PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H.data(), len_buf, sizeof(len_buf), S.data());
    return S;
}


// aes_gcm_ae - GCM-AE_K(IV, P, A)

static std::pair<std::vector<uint8_t>,std::vector<uint8_t>> aes_gcm_ae(const roundkey& rk, const std::vector<uint8_t>& iv,
           const std::vector<uint8_t>& plain,
           const std::vector<uint8_t>& aad) {
    aes_block H {};
    std::vector<uint8_t> tag;

    H = aes_encrypt(H, rk);

    aes_block const J0 = aes_gcm_prepare_j0(iv, H);
    std::vector<uint8_t> crypt;
    crypt.resize(plain.size());
    aes_gcm_gctr(rk, J0, plain.data(), plain.size(), crypt.data());
    
    auto S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    
    tag.resize(S.size());
    aes_gctr(rk, J0, S.data(), S.size(), tag.data());

    return {crypt, tag};
}



// aes_gcm_ad - GCM-AD_K(IV, C, A, T)

static std::vector<uint8_t> aes_gcm_ad(const roundkey& rk, const std::vector<uint8_t>& iv,
           const std::vector<uint8_t>& crypt,
                   const std::vector<uint8_t>& aad, const std::vector<uint8_t>& tag) {
    
    aes_block H {};
    aes_block T {};
    std::vector<uint8_t> plain;
    
    H = aes_encrypt(H, rk);
    aes_block const J0 = aes_gcm_prepare_j0(iv, H);
    plain.resize(crypt.size());
    aes_gcm_gctr(rk, J0, crypt.data(), crypt.size(), plain.data());
    std::vector<uint8_t> S = aes_gcm_ghash(H, aad, crypt.data(), crypt.size());
    aes_gctr(rk, J0, S.data(), S.size(), T.data());
    if(!std::equal(tag.begin(), tag.end(), T.begin())) [[unlikely]] {
        throw ssl_error("bad tag", AlertLevel::fatal, AlertDescription::bad_record_mac);
    }
    return plain;
}

[[maybe_unused]] static std::vector<uint8_t> aes_gmac(const roundkey& key, const std::vector<uint8_t>& iv,
         const std::vector<uint8_t>& aad) {
    assert(false);
    auto [_, tag] = aes_gcm_ae(key, iv, {}, aad);
    return tag;
}

void AES_128_GCM_SHA256::set_key_material_12(std::vector<uint8_t> material) {

    std::vector<uint8_t> client_write_key;
    client_write_key.resize(16);
    std::vector<uint8_t> server_write_key;
    server_write_key.resize(16);
    
    ctx.client_implicit_write_IV.resize(4);
    ctx.server_implicit_write_IV.resize(4);
    
    auto it = material.begin();
    std::copy_n(it, client_write_key.size(), client_write_key.begin());
    it += client_write_key.size();
    std::copy_n(it, server_write_key.size(), server_write_key.begin());
    it += server_write_key.size();
    std::copy_n(it, ctx.client_implicit_write_IV.size(), ctx.client_implicit_write_IV.begin());
    it += ctx.client_implicit_write_IV.size();
    std::copy_n(it, ctx.server_implicit_write_IV.size(), ctx.server_implicit_write_IV.begin());
    it += ctx.server_implicit_write_IV.size();
    
    ctx.client_write_round_keys = aes_key_schedule(client_write_key);
    ctx.server_write_round_keys = aes_key_schedule(server_write_key);
}

void AES_GCM_SHA2_ctx::set_server_key(const std::vector<uint8_t>& traffic_key, size_t key_size, size_t iv_size, const hash_base& hash_ctor) {
    seqno_server = 0;
    auto key = hkdf_expand_label(hash_ctor, traffic_key, "key", std::string(""), key_size);
    auto iv = hkdf_expand_label(hash_ctor, traffic_key, "iv", std::string(""), iv_size);
    std::vector<uint8_t> write_key(key_size);
    std::ranges::copy(key, write_key.begin());
    server_write_round_keys = aes_key_schedule(write_key);
    server_implicit_write_IV.resize(iv_size);
    std::ranges::copy(iv, server_implicit_write_IV.begin());
}

void AES_GCM_SHA2_ctx::set_client_key(const std::vector<uint8_t>& traffic_key, size_t key_size, size_t iv_size, const hash_base& hash_ctor) {
    seqno_client = 0;
    auto key = hkdf_expand_label(hash_ctor, traffic_key, "key", std::string(""), key_size);
    auto iv = hkdf_expand_label(hash_ctor, traffic_key, "iv", std::string(""), iv_size);
    std::vector<uint8_t> write_key(key_size);
    std::ranges::copy(key, write_key.begin());
    client_write_round_keys = aes_key_schedule(write_key);
    client_implicit_write_IV.resize(iv_size);
    std::ranges::copy(iv, client_implicit_write_IV.begin());
}

void AES_128_GCM_SHA256_tls13::set_server_traffic_key(const std::vector<uint8_t>& traffic_key) {
    ctx.set_server_key(traffic_key, KEY_SIZE, IV_SIZE, sha256());
}

void AES_128_GCM_SHA256_tls13::set_client_traffic_key(const std::vector<uint8_t>& traffic_key) {
    ctx.set_client_key(traffic_key, KEY_SIZE, IV_SIZE, sha256());
}

void AES_256_GCM_SHA384::set_server_traffic_key(const std::vector<uint8_t>& traffic_key) {
   ctx.set_server_key(traffic_key, KEY_SIZE, IV_SIZE, sha384());
}

void AES_256_GCM_SHA384::set_client_traffic_key(const std::vector<uint8_t>& traffic_key) {
    ctx.set_client_key(traffic_key, KEY_SIZE, IV_SIZE, sha384());
}

bool AES_256_GCM_SHA384::do_key_reset() {
    return ctx.seqno_client > (1ULL << 32) or ctx.seqno_server > (1ULL << 32);
}

bool AES_128_GCM_SHA256_tls13::do_key_reset() {
    return ctx.seqno_client > (1ULL << 32) or ctx.seqno_server > (1ULL << 32);
}

static std::vector<uint8_t> make_additional_12(const tls_record& record, uint64_t sequence_no, size_t tag_size) {
    assert(record.m_contents.size() >= tag_size);
    uint16_t msglen = htons(record.m_contents.size() - tag_size);
    std::vector<uint8_t> additional_data(sizeof(uint64_t), 0);
    checked_bigend_write(sequence_no, additional_data, 0, sizeof(uint64_t));
    additional_data.insert(additional_data.end(), {static_cast<uint8_t>(record.get_type()), record.get_major_version(), record.get_minor_version()});
    additional_data.resize(13);
    std::memcpy(&additional_data[11], &msglen, 2);
    return additional_data;
}

tls_record AES_128_GCM_SHA256::protect(tls_record record) noexcept {
    std::vector<uint8_t> const additional_data = make_additional_12(record, ctx.seqno_server, 0);
    std::vector<uint8_t> sequence_no;
    sequence_no.resize(8);
    checked_bigend_write(ctx.seqno_server, sequence_no, 0, sizeof(uint64_t));
    ctx.seqno_server++;

    std::vector<uint8_t> iv = ctx.server_implicit_write_IV;
    iv.insert(iv.end(), sequence_no.begin(), sequence_no.end());
    auto [ciphertext, auth_tag] = aes_gcm_ae(ctx.server_write_round_keys, iv, record.m_contents, additional_data);
    assert(auth_tag.size() == TAG_SIZE);
    assert(sequence_no.size() == sizeof(uint64_t));
    record.m_contents = sequence_no;
    record.m_contents.insert(record.m_contents.end(), ciphertext.begin(), ciphertext.end());
    record.m_contents.insert(record.m_contents.end(), auth_tag.begin(),  auth_tag.end());
    return record;
}

tls_record AES_128_GCM_SHA256_tls13::protect(tls_record record) noexcept {
    record = wrap13(std::move(record));
    std::vector<uint8_t> const additional_data = make_additional_13(record.m_contents, TAG_SIZE);
    std::vector<uint8_t> sequence_no;
    sequence_no.resize(sizeof(uint64_t));
    checked_bigend_write(ctx.seqno_server, sequence_no, 0, sizeof(uint64_t));
    ctx.seqno_server++;

    std::vector<uint8_t> iv = ctx.server_implicit_write_IV;
    for (size_t i = 0; i < 8; ++i) {
        iv[i + IV_SIZE - sizeof(ctx.seqno_server)] ^= sequence_no[i];
    }
    auto [ciphertext, auth_tag] = aes_gcm_ae(ctx.server_write_round_keys, iv, record.m_contents, additional_data);
    assert(auth_tag.size() == TAG_SIZE);

    record.m_contents = ciphertext;
    record.m_contents.insert(record.m_contents.end(), auth_tag.begin(), auth_tag.end());
    return record;
}

tls_record AES_256_GCM_SHA384::protect(tls_record record) noexcept {
    record = wrap13(std::move(record));
    std::vector<uint8_t> const additional_data = make_additional_13(record.m_contents, TAG_SIZE);
    std::vector<uint8_t> sequence_no;
    sequence_no.resize(sizeof(uint64_t));
    checked_bigend_write(ctx.seqno_server, sequence_no, 0, sizeof(uint64_t));
    ctx.seqno_server++;

    std::vector<uint8_t> iv = ctx.server_implicit_write_IV;
    for (size_t i = 0; i < 8; ++i) {
        iv[i + IV_SIZE - sizeof(ctx.seqno_server)] ^= sequence_no[i];
    }
    auto [ciphertext, auth_tag] = aes_gcm_ae(ctx.server_write_round_keys, iv, record.m_contents, additional_data);
    assert(auth_tag.size() == TAG_SIZE);
    record.m_contents = ciphertext;
    record.m_contents.insert(record.m_contents.end(), auth_tag.begin(), auth_tag.end());
    return record;
}

tls_record AES_128_GCM_SHA256::deprotect(tls_record record) {
    if(record.m_contents.size() < TAG_SIZE + sizeof(uint64_t)) [[unlikely]] {
        throw ssl_error("short record IV HMAC", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    std::vector<uint8_t> explicit_IV(8, 0);
    checked_bigend_write(ctx.seqno_client, explicit_IV, 0, 8);
    std::vector<uint8_t> const ciphertext(record.m_contents.begin() + sizeof(uint64_t), record.m_contents.end() - TAG_SIZE);
    std::vector<uint8_t> const auth_tag(record.m_contents.end() - TAG_SIZE, record.m_contents.end());
    std::vector<uint8_t> const additional_data = make_additional_12(record, ctx.seqno_client, 24);
    ctx.seqno_client++;
    assert(record.m_contents.size() >= auth_tag.size() + explicit_IV.size());
    auto iv = ctx.client_implicit_write_IV;
    iv.insert(iv.end(), explicit_IV.begin(), explicit_IV.end());
    std::vector<uint8_t> const plain = aes_gcm_ad(ctx.client_write_round_keys, iv, ciphertext, additional_data, auth_tag);
    record.m_contents = plain;
    if(record.m_contents.size() > TLS_RECORD_SIZE + DECRYPTED_TLS_RECORD_GIVE) [[unlikely]] {
        throw ssl_error("decrypted record too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    return record;
}

tls_record AES_128_GCM_SHA256_tls13::deprotect(tls_record record) {
    if(record.m_contents.size() < (TAG_SIZE + 1)) [[unlikely]] {
        throw ssl_error("short record IV HMAC", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    std::vector<uint8_t> iv(12, 0);
    checked_bigend_write(ctx.seqno_client, iv, 4, 8);
    for (size_t i = 0; i < 12; ++i) {
        iv[i] ^= ctx.client_implicit_write_IV[i];
    }
    std::vector<uint8_t> const ciphertext(record.m_contents.begin(), record.m_contents.end() - TAG_SIZE);
    std::vector<uint8_t> const auth_tag(record.m_contents.end() - TAG_SIZE, record.m_contents.end());
    std::vector<uint8_t> const additional_data = make_additional_13(record.m_contents, 0);
    ctx.seqno_client++;
    assert(record.m_contents.size() >= auth_tag.size() + 1);
    std::vector<uint8_t> const plain = aes_gcm_ad(ctx.client_write_round_keys, iv, ciphertext, additional_data, auth_tag);
    record.m_contents = plain;
    if(record.m_contents.size() > TLS_RECORD_SIZE + DECRYPTED_TLS_RECORD_GIVE) [[unlikely]] {
        throw ssl_error("decrypted record too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    record = unwrap13(std::move(record));
    return record;
}

tls_record AES_256_GCM_SHA384::deprotect(tls_record record) {
    if(record.m_contents.size() < (TAG_SIZE + 1)) [[unlikely]] {
        throw ssl_error("record too short for tag and wrap", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    std::vector<uint8_t> iv(12, 0);
    checked_bigend_write(ctx.seqno_client, iv, 4, 8);
    for (size_t i = 0; i < 12; ++i) {
        iv[i] ^= ctx.client_implicit_write_IV[i];
    }
    std::vector<uint8_t> const ciphertext(record.m_contents.begin(), record.m_contents.end() - TAG_SIZE);
    std::vector<uint8_t> const auth_tag(record.m_contents.end() - TAG_SIZE, record.m_contents.end());
    std::vector<uint8_t> const additional_data = make_additional_13(record.m_contents, 0);
    ctx.seqno_client++;
    assert(record.m_contents.size() >= auth_tag.size() + 1);
    std::vector<uint8_t> const plain = aes_gcm_ad(ctx.client_write_round_keys, iv, ciphertext, additional_data, auth_tag);
    record.m_contents = plain;
    if(record.m_contents.size() > TLS_RECORD_SIZE + DECRYPTED_TLS_RECORD_GIVE) [[unlikely]] {
        throw ssl_error("decrypted record too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    record = unwrap13(std::move(record));
    return record;
}

} // namespace fbw
