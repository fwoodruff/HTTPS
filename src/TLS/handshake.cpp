//
//  handshake.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/04/2024.
//

#include "handshake.hpp"

#include "Cryptography/one_way/keccak.hpp"
#include "PEMextract.hpp"
#include "Cryptography/assymetric/secp256r1.hpp"
#include "Cryptography/assymetric/x25519.hpp"
#include "../global.hpp"
#include "Cryptography/key_derivation.hpp"
#include "Cryptography/cipher/block_chain.hpp"
#include "Cryptography/cipher/galois_counter.hpp"
#include "Cryptography/cipher/chacha20poly1305.hpp"
#include "TLS_utils.hpp"

namespace fbw {

void key_schedule::client_hello_record(tls_record record, bool& can_heartbeat) {
    const auto& hello = record.m_contents;
    if(hello.empty()) {
        throw ssl_error("record is just a header", AlertLevel::fatal, AlertDescription::decode_error);
    }
    assert(hello.size() >= 1 and hello[0] == 1);

    size_t len = try_bigend_read(hello,1,3);
    if(len + 4 != hello.size()) {
        throw ssl_error("record length overflows", AlertLevel::fatal, AlertDescription::decode_error);
    }
    // client random
    m_client_random.resize(32);
    std::copy(&hello.at(6), &hello.at(38), m_client_random.begin());
    // session ID
    size_t idx = 38;
    size_t session_id_len = try_bigend_read(hello, idx, 1);
    if(session_id_len == 32) {
        client_session_id = std::array<uint8_t, 32>{};
        std::copy(&hello.at(idx+1), &hello.at(idx+33), client_session_id->begin());
    }

    idx += (session_id_len + 1);
    // cipher suites
    auto ciphers = der_span_read(hello, idx, 2);
    cipher = cipher_choice(ciphers);
    if(cipher == static_cast<uint16_t>(cipher_suites::TLS_FALLBACK_SCSV)) {
        throw ssl_error("unnecessary TLS 1.1 fallback", AlertLevel::fatal, AlertDescription::inappropriate_fallback);
    }

    // client version
    if ( hello.at(4) != 3 or hello.at(5) != 3 ) {
        throw ssl_error("unsupported version handshake", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    assert(hash_ctor);
    assert(handshake_hasher);

    idx += ciphers.size() + 2;
    // compression
    auto compression_methods = der_span_read(hello, idx, 1);
    if(std::find(compression_methods.begin(), compression_methods.end(), 0) == compression_methods.end()) {
        throw ssl_error("compression not supported", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    idx += (compression_methods.size() + 1);
    // extensions
    auto extensions = der_span_read(hello, idx, 2);
    ssize_t extensions_len = extensions.size();
    idx += 2;

    alpn = "http/1.1";

    while(extensions_len > 0) {
        size_t extension_type = try_bigend_read(hello, idx, 2);
        auto extension = der_span_read(hello, idx + 2, 2);
        extensions_len -= extension.size() + 4;
        if(extensions_len < 0) {
            throw ssl_error("record length overflows", AlertLevel::fatal, AlertDescription::decode_error);
        }
        switch(extension_type) {
            case 0x000a:
                break;
            case 0x0000: // SNI
                m_SNI = check_SNI(extension);
                break;
            case 0x000f: // Heartbeat
                {
                    ustring peer_may_send {0x00, 0x01, 0x00};
                    ustring peer_no_send { 0x00, 0x01, 0x02};
                    if(extension.size() == 3) {
                        if(std::equal(extension.begin(), extension.end(), peer_may_send.begin()) or
                            std::equal(extension.begin(), extension.end(), peer_no_send.begin())) {
                                can_heartbeat = true;
                        }
                    } else {
                        throw ssl_error("invalid heartbeat extension", AlertLevel::fatal, AlertDescription::illegal_parameter);
                    }
                }
                break;
            case 0x002b: // TLS 1.3
                tls13_available = is_tls13_supported(extension);
                if(tls13_available) {
                    // todo: ignore TLS 1.3 ciphers if this extension not present
                }
                break;
            case 0x0033: // key share
                client_public_key = extract_x25519_key(extension);
                break;
            default:
                break;
        }
        idx += extension.size() + 4;
    }
    handshake_hasher->update(hello);
}

tls_record key_schedule::server_hello_record(bool use_tls13, bool can_heartbeat ) {
    auto hello_record = tls_record(ContentType::Handshake);
    
    // handshake header and server version
    hello_record.m_contents.reserve(49); // fix me

    // server random
    m_server_random.resize(32);
    randomgen.randgen(m_server_random);

    hello_record.write1(HandshakeType::server_hello);
    hello_record.push_der(3);
    hello_record.write({3, 3});

    hello_record.write(m_server_random);

    // session_id
    if(use_tls13 and client_session_id.has_value()) {
        hello_record.write1(32);
        hello_record.write(*client_session_id); // session ID
    } else {
        hello_record.write1(0); // session ID
    }
    
    hello_record.write2(cipher);
    hello_record.write1(0); // no compression

    hello_extensions(hello_record, use_tls13, can_heartbeat); // todo: store each of the extensions sent by the client in a map, and then only return those

    hello_record.pop_der();

    assert(hello_record.m_contents.size() >= 4);
    assert(handshake_hasher != nullptr);
    handshake_hasher->update(hello_record.m_contents);

    return hello_record;
}

tls_record key_schedule::server_encrypted_extensions_record() {
    tls_record out(ContentType::Handshake);
    out.write1(HandshakeType::encrypted_extensions);
    out.push_der(3);
    out.push_der(2);
    out.pop_der();
    out.pop_der();
    return out;
}

tls_record key_schedule::server_certificate_record(bool use_tls13) {
    tls_record certificate_record(ContentType::Handshake);
    certificate_record.write1(HandshakeType::certificate);
    certificate_record.push_der(3);
    if(use_tls13) {
        certificate_record.write1(0);
    }
    certificates_serial(certificate_record);
    if(use_tls13) {
        certificate_record.write({0, 0});
    }
    certificate_record.pop_der();
    handshake_hasher->update(certificate_record.m_contents);
    return certificate_record;
}

[[nodiscard]] tls_record key_schedule::server_certificate_verify_record() const {
    tls_record record(ContentType::Handshake);
    record.write1(HandshakeType::server_key_exchange);
    record.push_der(3);
 
    auto certificate_private = privkey_from_file(option_singleton().key_file);

    auto hash_verify_context = handshake_hasher->hash();
    std::array<uint8_t, 32> signature_digest;
    std::copy_n(hash_verify_context.begin(), signature_digest.size(), signature_digest.begin());

    std::array<uint8_t, 32> csrn;
    randomgen.randgen(csrn);
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));

    record.write(signature);
    record.pop_der();
    return record;
}


void key_schedule::server_handshake_finished13_record() {
    server_handshake_hash = handshake_hasher->hash();
}

ustring key_schedule::client_handshake_finished13_record(tls_record record) {
    auto finished_hash = handshake_hasher->hash();

    // todo: scope
    auto client_application_traffic_secret = hkdf_expand_label(*hash_ctor, master_secret, "c ap traffic", server_handshake_hash, hash_ctor->get_hash_size());
    auto finished_key = hkdf_expand_label(*hash_ctor, client_application_traffic_secret, "finished", ustring{}, hash_ctor->get_hash_size());
    
    auto resumption_master_secret = hkdf_expand_label(*hash_ctor, master_secret, "res master", finished_hash, hash_ctor->get_hash_size());

    auto verify_data = do_hmac(*hash_ctor, finished_key, finished_hash);

    if(verify_data != record.m_contents.substr(4)){
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    return resumption_master_secret;
}

tls_record key_schedule::server_key_exchange_record() {
    randomgen.randgen(server_private_key_ephem);
    std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(server_private_key_ephem);
    
    // Record Header
    tls_record record(ContentType::Handshake);

    // Handshake Header
    record.m_contents.reserve(116);
    record.write1(HandshakeType::server_key_exchange);
    record.push_der(3);

    // Curve Info
    std::array<uint8_t,3> curve_info({static_cast<uint8_t>(ECCurveType::named_curve), 0x00, 0x00});
    checked_bigend_write(static_cast<size_t>(NamedGroup::x25519), curve_info, 1, 2);
    
    // Public Key
    ustring signed_empheral_key;
    signed_empheral_key.append(curve_info.cbegin(), curve_info.cend());
    signed_empheral_key.append({static_cast<uint8_t>(pubkey_ephem.size())});
    signed_empheral_key.append(pubkey_ephem.cbegin(), pubkey_ephem.cend());

    assert(hash_ctor != nullptr);
    auto hashctx = hash_ctor->clone();
    
    hashctx->update(m_client_random);
    hashctx->update(m_server_random);
    hashctx->update(signed_empheral_key);
    
    auto signature_digest_vec = hashctx->hash();
    assert(signature_digest_vec.size() == 32);
    std::array<uint8_t, 32> signature_digest;
    std::copy(signature_digest_vec.cbegin(), signature_digest_vec.cend(), signature_digest.begin());
    
    auto certificate_private = privkey_from_file(option_singleton().key_file);

    // Signature
    std::array<uint8_t, 32> csrn;
    randomgen.randgen(csrn);
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));
    ustring sig_header ({static_cast<uint8_t>(HashAlgorithm::sha256), // Signature Header
    static_cast<uint8_t>(SignatureAlgorithm::ecdsa), 0x00, 0x00});
    
    checked_bigend_write(signature.size(), sig_header, 2, 2);
    
    record.write(signed_empheral_key);
    record.write(sig_header);
    record.write(signature);

    assert(record.m_contents.size() >= 4);
    record.pop_der();

    handshake_hasher->update(record.m_contents);
    return record;
}

tls_record key_schedule::server_hello_done_record() {
    tls_record record(ContentType::Handshake);
    record.write1(HandshakeType::server_hello_done);
    record.push_der(3);
    record.pop_der();
    handshake_hasher->update(record.m_contents);
    return record;
}

tls_record key_schedule::server_handshake_finished12_record() {
    tls_record out(ContentType::Handshake);
    out.write1(HandshakeType::finished);
    out.push_der(3);
    
    assert(handshake_hasher);
    auto handshake_hash = handshake_hasher->hash();
    assert(handshake_hash.size() == 32);
    
    ustring server_finished = prf(*hash_ctor, master_secret, "server finished", handshake_hash, 12);
    
    out.write(server_finished);
    out.pop_der();
    return out;
}

bool key_schedule::is_middlebox_compatibility_mode() {
    assert(p_use_tls13);
    return (*p_use_tls13 and client_session_id != std::nullopt);
}

std::optional<tls_record> try_extract_record(ustring& input) {
    if (input.size() < TLS_HEADER_SIZE) {
        return std::nullopt;
    }
    tls_record out(static_cast<ContentType>(input[0]), input[1], input[2] );

    size_t record_size = try_bigend_read(input, 3, 2);
    if(record_size > TLS_RECORD_SIZE + TLS_EXPANSION_MAX) {
        throw ssl_error("record header size too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    if(input.size() < record_size + TLS_HEADER_SIZE) {
        return std::nullopt;
    }
    out.m_contents = input.substr(TLS_HEADER_SIZE, record_size);
    input = input.substr(TLS_HEADER_SIZE + record_size);
    return out;
}

void key_schedule::hello_extensions(tls_record& record, bool use_tls13, bool can_heartbeat) {
     // announces no support for vulnerable handshake renegotiation attacks
    const ustring handshake_reneg = { 0xff, 0x01, 0x00, 0x01, 0x00 };

    // announces application layer will use http/1.1
    ustring alpn_protocol_data { 0x00, 0x10, 0x00, 0x00, 0x00, 0x00 }; 
    auto http11 = to_unsigned("http/1.1");

    auto lenhttp11 = static_cast<uint8_t>(http11.size());
    alpn_protocol_data.push_back(lenhttp11);
    alpn_protocol_data.append(http11);
    checked_bigend_write(alpn_protocol_data.size() - 6, alpn_protocol_data, 4, 2);
    checked_bigend_write(alpn_protocol_data.size() - 4, alpn_protocol_data, 2, 2);

    // announces willingness to accept heartbeat records
    ustring heartbeat = { 0x00, 0x0f, 0x00, 0x01, 0x00 };

    // announces we will use TLS 1.3
    ustring tls13_ext = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };

    ustring key_share_ext = { 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
    if(use_tls13) {
        // compute x25519 keypair 
        randomgen.randgen(server_private_key_ephem);
        std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(server_private_key_ephem);
        key_share_ext.append(pubkey_ephem.begin(), pubkey_ephem.end());
    }

    record.push_der(2);

    if(use_tls13) {
        record.m_contents.append(tls13_ext);
        record.m_contents.append(key_share_ext);
    } else {
        //record.m_contents.append(alpn_protocol_data); // todo understand TLS 1.3 alpn
        record.m_contents.append(handshake_reneg);
    }
    if (can_heartbeat) {
        record.m_contents.append(heartbeat);
    }
    record.pop_der();
}


ustring key_schedule::client_key_exchange_receipt(tls_record record) {
    const auto& key_exchange = record.m_contents;
    
    static_cast<void>(key_exchange.at(0));
    assert(key_exchange[0] == static_cast<uint8_t>(HandshakeType::client_key_exchange));
    
    const size_t len = try_bigend_read(key_exchange, 1, 3);
    const size_t keylen = try_bigend_read(key_exchange, 4, 1);
    if(len + 4 != key_exchange.size() or len != keylen + 1) {
        throw ssl_error("bad key exchange", AlertLevel::fatal, AlertDescription::decode_error);
    }
    
    if(key_exchange.size() < 37) {
        throw ssl_error("bad public key", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::copy(&key_exchange[5], &key_exchange[37], client_public_key.begin());
    auto premaster_secret = fbw::curve25519::multiply(server_private_key_ephem, client_public_key);
    master_secret = prf(*hash_ctor, premaster_secret, "master secret", m_client_random + m_server_random, 48);

    handshake_hasher->update(record.m_contents);

    // AES_256_CBC_SHA256 has the largest amount of key material at 128 bytes
    auto key_material = prf(*hash_ctor,  master_secret, "key expansion", m_server_random + m_client_random, 128);
    return key_material;
}


std::pair<ustring, ustring> key_schedule::tls13_key_calc() const {
    auto handshake_context_hash = handshake_hasher->hash();
    auto shared_secret = fbw::curve25519::multiply(server_private_key_ephem, client_public_key);
    auto zero_hash = do_hash(*hash_ctor, ustring{});
    assert(hash_ctor != nullptr);
    auto early_secret = hkdf_extract(*hash_ctor, ustring{}, ustring(hash_ctor->get_hash_size(), 0) );
    auto derived_secret = hkdf_expand_label(*hash_ctor, early_secret, "derived", zero_hash, hash_ctor->get_hash_size());
    auto handshake_secret = hkdf_extract(*hash_ctor, derived_secret, shared_secret);
    
    return { handshake_secret, handshake_context_hash };
}

// once client sends over their supported ciphers
// if client supports ChaCha20 we enforce that
// otherwise if client supports AES-GCM/AES-CBC, we pick whichever their preference is
unsigned short key_schedule::cipher_choice(const std::span<const uint8_t>& s) {
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if(x == static_cast<uint16_t>(cipher_suites::TLS_FALLBACK_SCSV)) {
            return x;
        }
    }
    // for(size_t i = 0; i < s.size(); i += 2) {
    //    uint16_t x = try_bigend_read(s, i, 2);
    //    if(x == static_cast<uint16_t>(cipher_suites::TLS_CHACHA20_POLY1305_SHA256)) {
    //        *p_use_tls13 = true;
    //        *p_cipher_context = std::make_unique<cha::ChaCha20_Poly1305>();
    //        hash_ctor = std::make_unique<sha256>();
    //        handshake_hasher = hash_ctor->clone();
    //        return x;
    //    }
    // }
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)) {
            *p_cipher_context = std::make_unique<cha::ChaCha20_Poly1305>();
            hash_ctor = std::make_unique<sha256>();
            handshake_hasher = hash_ctor->clone();
            return x;
        }
    }
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if(x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)) {
            *p_cipher_context = std::make_unique<aes::AES_128_GCM_SHA256>();
            hash_ctor = std::make_unique<sha256>();
            handshake_hasher = hash_ctor->clone();
            return x;
        }
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)) {
            *p_cipher_context = std::make_unique<aes::AES_CBC_SHA>();
            hash_ctor = std::make_unique<sha256>();
            handshake_hasher = hash_ctor->clone();
            return x;
        }

    }
    throw ssl_error("no supported ciphers", AlertLevel::fatal, AlertDescription::handshake_failure );
}

void key_schedule::client_handshake_finished12_record(tls_record record) {
    
    static_cast<void>(record.m_contents.at(0));
    if(record.m_contents[0] != static_cast<uint8_t>(HandshakeType::finished)) {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    const size_t len = try_bigend_read(record.m_contents, 1, 3);
    if(len != 12) {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    auto finish = record.m_contents.substr(4);
    auto handshake_hash = handshake_hasher->hash();
    ustring expected_finished = prf(*hash_ctor, master_secret, "client finished", handshake_hash, 12);

    if(expected_finished != finish) {
        throw ssl_error("handshake verification failed", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    handshake_hasher->update(record.m_contents);
}


}
