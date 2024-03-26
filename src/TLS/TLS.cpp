//
//  TLS.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "TLS.hpp"

#include "Cryptography/assymetric/x25519.hpp"
#include "Cryptography/one_way/secure_hash.hpp"
#include "Cryptography/assymetric/secp256r1.hpp"
#include "PEMextract.hpp"
#include "TLS_enums.hpp"
#include "../global.hpp"
#include "Cryptography/one_way/keccak.hpp"
#include "Cryptography/cipher/block_chain.hpp"
#include "Cryptography/cipher/galois_counter.hpp"
#include "Cryptography/cipher/chacha20poly1305.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/tcp_stream.hpp"

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>

#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif

namespace fbw {


TLS::TLS(std::unique_ptr<stream> output_stream) : m_client(std::move(output_stream) ) {}


std::optional<tls_record> try_extract_record(ustring& input);

[[nodiscard]] task<bool> TLS::read_append(ustring& data, std::optional<milliseconds> timeout) {
    if(m_expected_record != HandshakeStage::application_data) {
        if(!co_await perform_handshake(timeout)) {
            co_return false;
        }
    }
    std::optional<ssl_error> error_ssl {};
    try {
        auto record = co_await try_read_record(timeout);
        if(!record) {
            co_return false;
        }
        switch ( static_cast<ContentType> (record->get_type()) ) {
            case ContentType::Handshake:
            case ContentType::ChangeCipherSpec:
                throw ssl_error("handshake already done", AlertLevel::fatal, AlertDescription::unexpected_message);
            case ContentType::Application:
                record = cipher_context->decrypt(std::move(*record));
                data.append(std::move(record->m_contents));
                co_return true;
            case ContentType::Alert:
                client_alert(std::move(*record));
                co_return false;
            case ContentType::Heartbeat:
                co_await client_heartbeat(std::move(*record), timeout);
                co_return true;
        }
    } catch(const ssl_error& e) {
        error_ssl = e;
        goto END; // cannot co_await inside a catch block
    } catch(const stream_error& e) {
        throw e;
    } catch(std::out_of_range& e) {
        // from options
        std::cerr << e.what() << std::endl;
    } catch(const std::exception& e) {
        throw stream_error(e.what());
    }
END:
    auto r = tls_record(ContentType::Alert);
    r.m_contents = { static_cast<uint8_t>(error_ssl->m_l), static_cast<uint8_t>(error_ssl->m_d) };
    if(error_ssl->m_d != AlertDescription::decrypt_error) {
        co_await write_record(std::move(r), timeout);
    }
    throw stream_error("bad TLS client");
}



[[nodiscard]] task<void> TLS::write(ustring data, std::optional<milliseconds> timeout) {
    if(m_expected_record != HandshakeStage::application_data) {
        if(!co_await perform_handshake(timeout)) {
            co_return;
        }
    }
    
    constexpr size_t RECORD_SIZE = 1300;
    size_t idx = 0;
    while(idx < data.size()) {
        ustring contents = data.substr(idx, RECORD_SIZE);
        idx += RECORD_SIZE;
        tls_record rec(ContentType::Application);
        rec.m_contents = contents;
        assert(m_expected_record == HandshakeStage::application_data);
        rec = cipher_context->encrypt(rec);
        co_await write_record(std::move(rec), timeout);
    }
}


[[nodiscard]] task<void> TLS::close_notify(std::optional<milliseconds> timeout) {
    tls_record rc { ContentType::Alert };
    rc.m_contents = { static_cast<uint8_t>(AlertLevel::warning) , static_cast<uint8_t>(AlertDescription::close_notify )};
    co_await write_record(rc, timeout);
}

task<bool> TLS::perform_handshake(std::optional<milliseconds> timeout) {
    //using enum ContentType;
    std::optional<ssl_error> error_ssl {};
    try {
        for(;;) {
            auto record = co_await try_read_record(timeout);
            if(!record) {
                co_return false;
            }
            
            switch ( static_cast<ContentType>(record->get_type()) ) {
                case ContentType::Handshake:
                    if(m_expected_record > HandshakeStage::client_change_cipher_spec) {
                        record = cipher_context->decrypt(std::move(*record));
                    }
                    co_await client_handshake_record(std::move(*record), timeout);
                    if(m_expected_record == HandshakeStage::application_data) {
                        co_return true;
                    }
                    break;
                case ContentType::ChangeCipherSpec:
                    client_change_cipher_spec(std::move(*record));
                    break;
                case ContentType::Application:
                    throw ssl_error("handshake not done yet", AlertLevel::fatal, AlertDescription::unexpected_message);
                case ContentType::Alert:
                    client_alert(std::move(*record));
                    co_return false;
                    break;
                case ContentType::Heartbeat:
                    co_await client_heartbeat(std::move(*record), timeout);
                    break;
            }
        }
    } catch(const ssl_error& e) {
        error_ssl = e;
        goto END; // cannot co_await inside a catch block
    } catch(const stream_error& e) {
        throw e;
    } catch(const std::exception& e) {
        throw stream_error(e.what());
    }
END:
    auto r = tls_record(ContentType::Alert);
    r.m_contents = { static_cast<uint8_t>(error_ssl->m_l), static_cast<uint8_t>(error_ssl->m_d) };
    if(error_ssl->m_d != AlertDescription::decrypt_error) {
        co_await write_record(std::move(r), timeout);
    }
    throw stream_error("bad TLS client");
}

task<std::optional<tls_record>> TLS::try_read_record(std::optional<milliseconds> timeout) {
    for(;;) {
        if (m_buffer.size() > TLS_RECORD_SIZE + 6) {
            throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
        }
        auto record = try_extract_record(m_buffer);
        
        if(record) {
            if (record->get_major_version() != 3) {
                throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
            }
            co_return *record;
        }
        bool connection_alive = co_await m_client->read_append(m_buffer, timeout);
        if(!connection_alive) {
            co_return std::nullopt;
        }
    }
}

task<void> TLS::write_record(tls_record record, std::optional<milliseconds> timeout) {
    ustring ust = record.serialise();
    try {
        co_await m_client->write(ust, timeout);
    } catch(const stream_error& e) {
        throw e;
    }
}

task<void> TLS::client_handshake_record(tls_record record, std::optional<milliseconds> timeout) {
    ustring handshake_record = record.m_contents;
    switch (handshake_record.at(0)) {
        case static_cast<uint8_t>(HandshakeType::hello_request):
            throw ssl_error("hello_request not supported", AlertLevel::fatal, AlertDescription::handshake_failure);
        case static_cast<uint8_t>(HandshakeType::client_hello):
            client_hello(std::move(record));
            co_await server_hello(timeout);
            co_await server_certificate(timeout);
            co_await server_key_exchange(timeout);
            co_await server_hello_done(timeout);
            break;
        case static_cast<uint8_t>(HandshakeType::client_key_exchange):
            client_key_exchange(std::move(record));
            break;
        case static_cast<uint8_t>(HandshakeType::finished):
            client_handshake_finished(std::move(record));
            co_await server_change_cipher_spec(timeout);
            co_await server_handshake_finished(timeout);
            break;
        default:
            throw ssl_error("unsupported handshake record type", AlertLevel::fatal, AlertDescription::handshake_failure);
            break;
    }
}


std::optional<tls_record> try_extract_record(ustring& input) {
    if (input.size() < 5) {
        return std::nullopt;
    }
    tls_record out(static_cast<ContentType>(input[0]), input[1], input[2] );

    size_t record_size = try_bigend_read(input,3,2);
    if(input.size() < record_size + 5) {
        return std::nullopt;
    }
    out.m_contents = input.substr(5, record_size);
    input = input.substr(5 + record_size);
    return out;
}

bool check_SNI(ustring servernames) {
    // Server name
    try {
        while(!servernames.empty()) {
            size_t entry_len = try_bigend_read(servernames, 0, 2);
            ustring entry = servernames.substr(2, entry_len);
            
            switch(entry.at(0)) {
                case 0: // DNS hostname
                {
                    size_t name_len = try_bigend_read(entry, 1, 2);
                    const auto subdomain_name = entry.substr(3);
                    
                    if(name_len != subdomain_name.size()) {
                        return false;
                    }
                    auto domain_names = get_multi_option("DOMAIN_NAMES");
                    auto str_domain_name = to_signed(subdomain_name);
                    for(auto name : domain_names) {
                        if (name == str_domain_name) {
                            return true;
                        }
                    }
                    break;
                }
                default:
                    break;
            }
            servernames = servernames.substr(entry_len + 2);
        }
    } catch(...) { }
    return false;
}

 
void TLS::client_hello(tls_record record) {
    if(m_expected_record != HandshakeStage::client_hello) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    auto hello = record.m_contents;
    if(hello.empty()) {
        throw ssl_error("bad hello", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    assert(hello.size() >= 1 and hello[0] == 1);
    
    size_t len = try_bigend_read(hello,1,3);
    if(len + 4 != hello.size()) {
        throw ssl_error("bad hello", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    // client version
    if ( hello.at(4) != 3 or hello.at(5) != 3 ) {
        throw ssl_error("unsupported version handshake", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    // client random
    std::copy(&hello.at(6), &hello.at(38), m_client_random.begin());
    // session ID
    size_t idx = 38;
    idx += try_bigend_read(hello, idx, 1) + 1;
    // cipher suites
    size_t ciphers_len = try_bigend_read(hello, idx, 2);
    static_cast<void>(hello.at(idx+ ciphers_len + 2));
    cipher = cipher_choice(hello.substr(idx + 2, ciphers_len));
    
    idx += ciphers_len + 2;
    // compression
    if(hello.at(idx) != 1 and hello.at(idx + 1) != 0) {
        throw ssl_error("compression not supported", AlertLevel::fatal, AlertDescription::decompression_failure);
    }
    idx += 2;
    // extensions
    ssize_t extensions_len = try_bigend_read(hello,idx,2);

    idx += 2;
    while(extensions_len > 0) {
        size_t extension_type = try_bigend_read(hello, idx, 2);
        size_t extension_len = try_bigend_read(hello, idx + 2, 2);
        ustring extension = hello.substr(idx + 4, extension_len);
        switch(extension_type) {
            case 0x000a:
                break;
            case 0x0000:
                if(!check_SNI(extension)) {
                    throw ssl_error("bad SNI", AlertLevel::fatal, AlertDescription::handshake_failure);
                }
            default:
                break;
        }
        idx += extension_len + 4;
        extensions_len -= extension_len + 4;
    }
    
    if(extensions_len != 0) {
        throw ssl_error("bad extension", AlertLevel::fatal, AlertDescription::internal_error);
    }

    handshake_hasher->update(hello);
    m_expected_record = HandshakeStage::server_hello;
}

task<void> TLS::server_hello(std::optional<milliseconds> timeout) {
    assert(m_expected_record == HandshakeStage::server_hello);
    auto hello_record = tls_record(ContentType::Handshake);
    
    hello_record.m_contents.reserve(49);
    hello_record.m_contents = {static_cast<uint8_t>(HandshakeType::server_hello), 0x00, 0x00, 0x00, 0x03, 0x03};
    
    randomgen.randgen(m_server_random.data(), 32);
    hello_record.m_contents.append(m_server_random.cbegin(), m_server_random.cend());
    hello_record.m_contents.append({0}); // session ID
    ustring ciph;
    ciph.resize(2);
    checked_bigend_write(cipher, ciph, 0, 2);
    hello_record.m_contents.append(ciph);
    hello_record.m_contents.append({0}); // no compression
    hello_record.m_contents.append({0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00}); // extensions
    assert(hello_record.m_contents.size() >= 4);
    checked_bigend_write(hello_record.m_contents.size() - 4, hello_record.m_contents, 1, 3);

    assert(handshake_hasher != nullptr);
    handshake_hasher->update(hello_record.m_contents);
    
    co_await write_record(hello_record, timeout);
    m_expected_record = HandshakeStage::server_certificate;
}

task<void> TLS::server_certificate(std::optional<milliseconds> timeout) {
    assert(m_expected_record == HandshakeStage::server_certificate);
    tls_record certificate_record(ContentType::Handshake);
    certificate_record.m_contents = {static_cast<uint8_t>(HandshakeType::certificate), 0,0,0, 0,0,0};
    std::string cert_file;
    try {
        cert_file = get_option("CERTIFICATE_FILE");
    } catch(...) {
        std::cerr << "configure TLS certificates" << std::endl;
        std::terminate();
    }
    const auto certs = der_cert_from_file(get_option("CERTIFICATE_FILE"));
    for (const auto& cert : certs) {
        ustring cert_header;
        cert_header.append({0, 0, 0});
        checked_bigend_write(cert.size(), cert_header, 0, 3);
        certificate_record.m_contents.append(cert_header);
        certificate_record.m_contents.append(cert);
    }
    assert(certificate_record.m_contents.size() >= 7);
    checked_bigend_write(certificate_record.m_contents.size() - 4, certificate_record.m_contents, 1, 3);
    checked_bigend_write(certificate_record.m_contents.size() - 7, certificate_record.m_contents, 4, 3);

    co_await write_record(certificate_record, timeout);
    handshake_hasher->update(certificate_record.m_contents);
    m_expected_record = HandshakeStage::server_key_exchange;
}

task<void> TLS::server_key_exchange(std::optional<milliseconds> timeout) {
    randomgen.randgen(server_private_key_ephem.begin(), server_private_key_ephem.size());
    std::array<uint8_t, 32> privrev;
    std::reverse_copy(server_private_key_ephem.cbegin(), server_private_key_ephem.cend(), privrev.begin());
    std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(privrev);
    std::reverse(pubkey_ephem.begin(), pubkey_ephem.end());

    tls_record record(ContentType::Handshake);

    record.m_contents.reserve(116);
    record.m_contents = { static_cast<uint8_t>(HandshakeType::server_key_exchange), 0x00, 0x00, 0x00 };
    std::array<uint8_t,3> curve_info({static_cast<uint8_t>(ECCurveType::named_curve), 0x00, 0x00});
    
    checked_bigend_write(static_cast<size_t>(NamedCurve::x25519), curve_info, 1, 2);
    
    ustring signed_empheral_key;
    signed_empheral_key.append(curve_info.cbegin(), curve_info.cend());
    signed_empheral_key.append({static_cast<uint8_t>(pubkey_ephem.size())});
    signed_empheral_key.append(pubkey_ephem.cbegin(), pubkey_ephem.cend());

    assert(hasher_factory != nullptr);
    auto hashctx = hasher_factory->clone();
    
    hashctx->update(m_client_random);
    hashctx->update(m_server_random);
    hashctx->update(signed_empheral_key);
    
    auto signature_digest_vec = hashctx->hash();
    assert(signature_digest_vec.size() == 32);
    std::array<uint8_t, 32> signature_digest;
    std::copy(signature_digest_vec.cbegin(), signature_digest_vec.cend(), signature_digest.begin());
    
    
    std::string priv_key;
    try {
        priv_key = get_option("KEY_FILE");
    } catch(...) {
        std::cerr << "please configure private key" << std::endl;
        std::terminate();
    }
    auto certificate_private = privkey_from_file(get_option("KEY_FILE"));

    std::array<uint8_t, 32> csrn;
    randomgen.randgen( csrn.begin(), csrn.size());
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));
    ustring sig_header ({static_cast<uint8_t>(HashAlgorithm::sha256),
        static_cast<uint8_t>(SignatureAlgorithm::ecdsa), 0x00, 0x00});
    
    checked_bigend_write(signature.size(), sig_header, 2, 2);
    
    record.m_contents.append(signed_empheral_key);
    record.m_contents.append(sig_header);
    record.m_contents.append(signature);

    assert(record.m_contents.size() >= 4);
    checked_bigend_write(record.m_contents.size()-4, record.m_contents, 1, 3);
    
    co_await write_record(record, timeout);
    handshake_hasher->update(record.m_contents);
    m_expected_record = HandshakeStage::server_hello_done;
}

task<void> TLS::server_hello_done(std::optional<milliseconds> timeout) {
    assert(m_expected_record == HandshakeStage::server_hello_done);
    tls_record record(ContentType::Handshake);
    record.m_contents = { static_cast<uint8_t>(HandshakeType::server_hello_done), 0x00, 0x00, 0x00 };
    co_await write_record(record, timeout);
    handshake_hasher->update(record.m_contents);
    m_expected_record = HandshakeStage::client_key_exchange;
}

void TLS::client_key_exchange(tls_record record) {
    auto key_exchange = record.m_contents;
    if(m_expected_record != HandshakeStage::client_key_exchange) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    static_cast<void>(key_exchange.at(0));
    assert(key_exchange[0] == static_cast<uint8_t>(HandshakeType::client_key_exchange));
    
    const size_t len = try_bigend_read(key_exchange, 1, 3);
    const size_t keylen = try_bigend_read(key_exchange, 4, 1);
    if(len + 4 != key_exchange.size() or len != keylen + 1) {
        throw ssl_error("bad key exchange", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    
    if(key_exchange.size() < 37) {
        throw ssl_error("bad public key", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::copy(&key_exchange[5], &key_exchange[37], client_public_key.begin());
    
    if(!hasher_factory) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    master_secret = make_master_secret(hasher_factory, server_private_key_ephem, client_public_key, m_server_random, m_client_random);
    
    // AES_256_CBC_SHA256 has the largest amount of key material at 128 bytes
    ustring key_material = expand_master(master_secret, m_server_random, m_client_random, 128);
    
    cipher_context->set_key_material(key_material);
    handshake_hasher->update(key_exchange);
    m_expected_record = HandshakeStage::client_change_cipher_spec;
}

void TLS::client_change_cipher_spec(tls_record record) {
    auto change_message = record.m_contents;
    if(m_expected_record != HandshakeStage::client_change_cipher_spec) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    if(change_message.size() != 1 and change_message.at(0) != static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)) {
        throw ssl_error("bad cipher spec", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    m_expected_record = HandshakeStage::client_handshake_finished;
}

void TLS::client_handshake_finished(tls_record record) {
    auto finish = record.m_contents;
    if(m_expected_record != HandshakeStage::client_handshake_finished) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    static_cast<void>(finish.at(0));
    assert(finish[0] == static_cast<uint8_t>(HandshakeType::finished));
    
    const size_t len = try_bigend_read(finish,1,3);
    if(len != 12) {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    const std::string seed_signed = "client finished";
    ustring seed;
    seed.append(seed_signed.cbegin(), seed_signed.cend());
    if(!handshake_hasher) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    auto local_hasher = handshake_hasher->clone();
    auto handshake_hash = local_hasher->hash();
    seed.append(handshake_hash.cbegin(), handshake_hash.cend());

    const auto ctx = hmac(hasher_factory->clone(), master_secret);
    
    auto ctx2 = ctx;
    auto a1 = ctx2
        .update(seed)
        .hash();
    auto p1 = (ctx2 = ctx)
        .update(a1)
        .update(seed)
        .hash();
    
    bool eq = true;
    for(int i = 0; i < 12; i ++) {
        if(finish.at(i+4) != p1.at(i)) {
            eq = false;
        }
    }
    
    if(eq == false) {
        throw ssl_error("handshake verification failed", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    
    handshake_hasher->update(finish);
    m_expected_record = HandshakeStage::server_change_cipher_spec;
}

task<void> TLS::server_change_cipher_spec(std::optional<milliseconds> timeout) {
    assert(m_expected_record == HandshakeStage::server_change_cipher_spec);
    tls_record record { ContentType::ChangeCipherSpec };
    record.m_contents = {static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)};
    co_await write_record(record, timeout);
    m_expected_record = HandshakeStage::server_handshake_finished;
}

task<void> TLS::server_handshake_finished(std::optional<milliseconds> timeout) {
    assert(m_expected_record == HandshakeStage::server_handshake_finished);
    tls_record out(ContentType::Handshake);
    out.m_contents = { static_cast<uint8_t>(HandshakeType::finished), 0x00, 0x00, 0x0c };
    
    const std::string SERVER_HANDSHAKE_SEED = "server finished";
    ustring seed;
    seed.append(SERVER_HANDSHAKE_SEED.cbegin(),SERVER_HANDSHAKE_SEED.cend());
    
    if(!handshake_hasher) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    auto local_hasher = handshake_hasher->clone(); // the others?
    auto handshake_hash = local_hasher->hash();
    assert(handshake_hash.size() == 32);
    seed.append(handshake_hash.begin(), handshake_hash.end());

    const auto ctx = hmac(hasher_factory->clone(), master_secret);
    auto ctx2 = ctx;
    
    auto a1 = (ctx2 = ctx)
        .update(seed)
        .hash();

    auto p1 = (ctx2 = ctx)
        .update(a1)
        .update(seed)
        .hash();
    
    assert(p1.size() >= 12);
    out.m_contents.append(&p1[0], &p1[12]);
    if(m_expected_record <= HandshakeStage::server_change_cipher_spec) {
        throw ssl_error("Unwilling to respond on unencrypted channel", AlertLevel::fatal, AlertDescription::insufficient_security);
    }
    out = cipher_context->encrypt(out);
    
    co_await write_record(out, timeout);
    m_expected_record = HandshakeStage::application_data;
}

void TLS::client_alert(tls_record record) {
    auto alert_message = record.m_contents;
    if(alert_message.size() != 2) {
        throw ssl_error("bad alert", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    switch(alert_message[0]) {
        case static_cast<uint8_t>(AlertLevel::warning):
            switch(alert_message[1]) {
                case static_cast<uint8_t>(AlertDescription::close_notify):
                    return;
                default:
                    goto flag;
            }
            break;
        default:
            flag:
            throw ssl_error("unsupported alert", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
}

task<void> TLS::client_heartbeat(tls_record record, std::optional<milliseconds> timeout) {
    auto heartbeat_message = record.m_contents;
    // fix me
    if(heartbeat_message.size() != 1 or heartbeat_message[0] != 0x01) {
        throw ssl_error("heartbleed", AlertLevel::fatal, AlertDescription::access_denied);
    }
    tls_record heartbeat_record( ContentType::Heartbeat);
    heartbeat_record.m_contents = {2};
    co_await write_record(heartbeat_record, timeout);
}

std::array<uint8_t,48> TLS::make_master_secret(const std::unique_ptr<const hash_base>& hash_factory,
                                               std::array<uint8_t, 32> server_private,
                                                std::array<uint8_t, 32> client_public,
                                                std::array<uint8_t, 32> server_random,
                                                std::array<uint8_t, 32> client_random) {
    std::reverse(server_private.begin(), server_private.end());
    std::reverse(client_public.begin(), client_public.end());
    auto premaster_secret = fbw::curve25519::multiply(server_private, client_public);
    std::reverse(premaster_secret.begin(), premaster_secret.end());
    
    std::string seedsi = "master secret";
    ustring seed;
    seed.append(seedsi.cbegin(),seedsi.cend());
    seed.append(client_random.cbegin(), client_random.cend());
    seed.append(server_random.cbegin(), server_random.cend());
    
    const auto ctx = hmac(hash_factory->clone(), premaster_secret);
    auto ctx2 = ctx;
    auto a1 = (ctx2 = ctx)
                    .update(seed)
                    .hash();
    assert(a1.size() == 32);
    auto a2 = (ctx2 = ctx)
                    .update(a1)
                    .hash();
    auto p1 = (ctx2 = ctx)
                    .update(a1)
                    .update(seed)
                    .hash();
    auto p2 = (ctx2 = ctx)
                    .update(a2)
                    .update(seed)
                    .hash();

    std::array<uint8_t,48> master_secret;
    assert(p2.size() >= 16);
    std::copy(p1.cbegin(), p1.cend(), master_secret.begin());
    std::copy(p2.begin(), p2.begin() + 16, &master_secret[32]);
    
    return master_secret;
}

// once client sends over their supported ciphers
// if client supports ChaCha20 we enforce that
// otherwise if client supports AES-GCM/AES-CBC, we pick whichever their preference is
unsigned short TLS::cipher_choice(const ustring& s) {
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)) {
            cipher_context = std::make_unique<cha::ChaCha20_Poly1305>();
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            return x;
        }
    }
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if(x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)) {
            cipher_context = std::make_unique<aes::AES_128_GCM_SHA256>();
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            return x;
        }
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)) {
            cipher_context = std::make_unique<aes::AES_CBC_SHA>();
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            return x;
        }

    }
    throw ssl_error("no supported ciphers", AlertLevel::fatal, AlertDescription::handshake_failure );
    return 0;
}

ustring TLS::expand_master(const std::array<unsigned char,48>& master,
                          const std::array<unsigned char,32>& server_random,
                          const std::array<unsigned char,32>& client_random, size_t len) const {
    
    assert(hasher_factory != nullptr);
    ustring output;
    const std::string seed = "key expansion";
    ustring useed;
    useed.append(seed.cbegin(), seed.cend());
    useed.append(server_random.cbegin(), server_random.cend());
    useed.append(client_random.cbegin(), client_random.cend());
    auto a = useed;

    const auto ctx = hmac(hasher_factory->clone(), master);
    auto ctx2 = ctx;
    while(output.size() < len) {
        ctx2 = ctx;
        ctx2.update(a);
        auto ou = ctx2.hash();
        a.clear();
        a.append(ou);
        ctx2 = ctx;
        ctx2.update(a)
            .update(useed);
        ou = ctx2.hash();
        output.append(ou);
    }
    output.resize(len);
    return output;
}

}// namespace fbw



