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
#include "hello.hpp"
#include "session_ticket.hpp"

namespace fbw {

// once client sends over their supported ciphers
// if client supports ChaCha20 we enforce that, ideally with TLS 1.3
// otherwise if client supports AES-GCM/AES-CBC, we pick whichever their preference is
cipher_suites choose_cipher(const hello_record_data& rec) {
     if(rec.legacy_client_version > TLS12) {
        throw ssl_error("legacy TLS version should always be TLS 1.2 or earlier", AlertLevel::fatal, AlertDescription::decode_error);
    }
    if(rec.legacy_client_version < TLS11) {
        throw ssl_error("TLS 1.0 and earlier are insufficiently secure", AlertLevel::fatal, AlertDescription::protocol_version);
    }
    if(auto it = std::find(rec.cipher_su.begin(), rec.cipher_su.end(), cipher_suites::TLS_FALLBACK_SCSV); it != rec.cipher_su.end()) {
        switch(rec.legacy_client_version) {
            case TLS11:
                throw ssl_error("client supports TLS 1.2 but offers TLS 1.1 downgrade", AlertLevel::fatal, AlertDescription::inappropriate_fallback);
            case TLS12:
                throw ssl_error("inconsistent description of client version", AlertLevel::fatal, AlertDescription::decode_error);
            default:
                assert(false);
        }
    }
    if(rec.legacy_client_version == TLS11) {
        throw ssl_error("TLS 1.1 not supported", AlertLevel::fatal, AlertDescription::protocol_version);
    }
    bool TLS12_support = false;
    if(auto it = std::find(rec.supported_versions.begin(), rec.supported_versions.end(), TLS12); it != rec.supported_versions.end() or rec.supported_versions.empty()) {
        TLS12_support = true;
    }
    bool TLS13_support = false;
    if(auto it = std::find(rec.supported_versions.begin(), rec.supported_versions.end(), TLS13); it != rec.supported_versions.end()) {
        TLS13_support = true;
    }

    // RFC 8446 4.1.2:
    //      If the list contains cipher suites that the server does not recognize, support, or wish to use,
    //      the server MUST ignore those cipher suites and process the remaining ones as usual.
    // How much freedom this gives the server is open to interpretation.
    // Is the server allowed to decide which ciphers it 'wishes to use' *after* receiving the client hello?
    // - This gets flagged as noncompliant by https://github.com/drwetter/testssl.sh
    // - This results in an observed ~2x download speed improvement on various machines
    if(TLS13_support) {
        if(auto it = std::find(rec.cipher_su.begin(), rec.cipher_su.end(), cipher_suites::TLS_CHACHA20_POLY1305_SHA256); it != rec.cipher_su.end()) {
            return cipher_suites::TLS_CHACHA20_POLY1305_SHA256;
        }
    }

    for(auto ciph : rec.cipher_su) {
        switch(ciph) {
            case cipher_suites::TLS_CHACHA20_POLY1305_SHA256: [[fallthrough]];
            case cipher_suites::TLS_AES_128_GCM_SHA256: [[fallthrough]];
            case cipher_suites::TLS_AES_256_GCM_SHA384:
                if(TLS13_support) {
                    return ciph;
                }
                break;
            case cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: [[fallthrough]];
            case cipher_suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            case cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
                if(TLS12_support) {
                    return ciph;
                }
                break;
            default:
                break;
        }
    }
    throw ssl_error("no supported ciphers", AlertLevel::fatal, AlertDescription::handshake_failure );
}

void CRIME_compression(const hello_record_data& client_hello) {
    if(std::find(client_hello.compression_types.begin(), client_hello.compression_types.end(), 0) == client_hello.compression_types.end()) {
        throw ssl_error("compression not supported", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
}

void handshake_ctx::set_cipher_ctx(cipher_suites cipher_suite) {
    cipher = cipher_suite;
    switch(cipher_suite) {
        case cipher_suites::TLS_AES_128_GCM_SHA256:
            *p_tls_version = TLS13;
            *p_cipher_context = std::make_unique<aes::AES_128_GCM_SHA256_tls13>();
            hash_ctor = std::make_unique<sha256>();
            break;
        case cipher_suites::TLS_AES_256_GCM_SHA384:
            *p_tls_version = TLS13;
            *p_cipher_context = std::make_unique<aes::AES_256_GCM_SHA384>();
            hash_ctor = std::make_unique<sha384>();
            break;
        case cipher_suites::TLS_CHACHA20_POLY1305_SHA256:
            *p_tls_version = TLS13;
            *p_cipher_context = std::make_unique<cha::ChaCha20_Poly1305_tls13>();
            hash_ctor = std::make_unique<sha256>();
            break;
        case cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            *p_tls_version = TLS12;
            *p_cipher_context = std::make_unique<aes::AES_128_GCM_SHA256>();
            hash_ctor = std::make_unique<sha256>();
            break;
        case cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            *p_tls_version = TLS12;
            *p_cipher_context = std::make_unique<aes::AES_CBC_SHA>();
            hash_ctor = std::make_unique<sha256>();
            break;
        case cipher_suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            *p_tls_version = TLS12;
            *p_cipher_context = std::make_unique<cha::ChaCha20_Poly1305_tls12>();
            hash_ctor = std::make_unique<sha256>();
            break;
        
        default:
            assert(false);
    }
    handshake_hasher = hash_ctor->clone();
}

std::string choose_alpn(const std::vector<std::string>& client_alpn) {
    if(client_alpn.empty()) {
        return "http/1.1";
    }
    if(std::find(client_alpn.begin(), client_alpn.end(), "h2") != client_alpn.end()) {
        // todo: toggle
        // return "h2";
    }
    if(std::find(client_alpn.begin(), client_alpn.end(), "http/1.1") == client_alpn.end()) {
        throw ssl_error("no supported application layer protocols", AlertLevel::fatal, AlertDescription::no_application_protocol);
    }
    return "http/1.1";
}

std::string choose_server_name(const std::vector<std::string>& server_names) {
    if(server_names.empty() or project_options.domain_names.empty()) {
        return "";
    }
    for(const auto& n : project_options.domain_names) {
        for(const auto& m :server_names) {
            if(n == m) {
                return n;
            }
        }
    }
    throw ssl_error("unrecognised name", AlertLevel::fatal, AlertDescription::unrecognized_name);
}

key_share choose_client_public_key(const std::vector<key_share>& keys, const std::vector<NamedGroup>& groups) {
    if(keys.empty()) {
        throw ssl_error("no keys sent", AlertLevel::fatal, AlertDescription::decode_error);
    }
    for(const auto& key : keys) {
        if(std::find(groups.begin(), groups.end(), key.key_type) == groups.end()) {
            throw ssl_error("key share not supported", AlertLevel::fatal, AlertDescription::illegal_parameter);
        }
    }
    for(const auto& key : keys) {
        switch(key.key_type) {
            case NamedGroup::x25519:
                if(key.key.size() != 32) {
                    throw ssl_error("bad key length", AlertLevel::fatal, AlertDescription::illegal_parameter);
                }
                return key;
            case NamedGroup::secp256r1:
                if(key.key.size() != 65) {
                    throw ssl_error("bad key length", AlertLevel::fatal, AlertDescription::illegal_parameter);
                }
                return key;
            default:
                break;
        }
    }
    for(const auto& group : groups) {
        switch(group) {
            case NamedGroup::x25519:
            case NamedGroup::secp256r1:
                return key_share{ group, {} };
            default:
                break;
        }
    }
    throw ssl_error("named group mismatch", AlertLevel::fatal, AlertDescription::handshake_failure);
}

tls_record synthetic_message_hash(const hash_base& hash_ctor, const ustring& client_hello) {
    tls_record record(ContentType::Handshake);
    record.write1(HandshakeType::message_hash);
    record.start_size_header(3);
    auto ctx = hash_ctor.clone();
    ctx->update(client_hello);
    record.write(ctx->hash());
    record.end_size_header();
    return record;
}

std::pair<ustring, std::optional<size_t>> handshake_ctx::get_resumption_psk(const ustring& hello_message) const {
    auto key = client_hello.pre_shared_key;
    assert(hash_ctor != nullptr);
    auto null_psk = ustring(hash_ctor->get_hash_size(), 0);
    if(!key) {
        return {null_psk, std::nullopt};
    }
    if(client_hello.pre_shared_key->idxbinders > hello_message.size()) {
        return {null_psk, std::nullopt};
    } 
    
    const std::span<const uint8_t> truncated_hello( hello_message.begin(), hello_message.begin() + client_hello.pre_shared_key->idxbinders );

    for(int i = 0; i < key->m_keys.size(); i++) { 
        auto key_entry = key->m_keys[i];
        auto ticket = TLS13SessionTicket::decrypt(key_entry.m_key, {});
        if(!ticket) {
            continue;
        }
        if(ticket->version != 1) {
            continue;
        }
        if(ticket->cipher_suite != cipher) {
            continue;
        }
        if(ticket->sni != "" && ticket->sni != m_SNI) {
            continue;
        }
        if(ticket->early_data_allowed == true) {
            continue; // not implemented yet
        }
        uint64_t computed_age_millis = uint32_t(key_entry.m_obfuscated_age - ticket->ticket_age_add);
        uint64_t lifetime_millis = uint64_t(ticket->ticket_lifetime) * 1000ull;
        if(computed_age_millis > lifetime_millis ) {
            continue;
        }
        if(ticket->resumption_secret.size() != hash_ctor->get_hash_size()) {
            continue;
        }
        if(i >= key->m_psk_binder_entries.size()) {
            break;
        }
        auto received_binder = client_hello.pre_shared_key->m_psk_binder_entries[i];
        ustring computed_binder = compute_binder(*hash_ctor, ticket->resumption_secret, truncated_hello);
        if(received_binder != computed_binder ) {
            continue;
        }
        return {ticket->resumption_secret, i};
    }
    return {null_psk, std::nullopt};
}

void handshake_ctx::client_hello_record(const ustring& handshake_message) {
    client_hello = parse_client_hello(handshake_message);
    if(hello_retry_count == 0) {
        auto cipher_id = choose_cipher(client_hello);
        set_cipher_ctx(cipher_id); 
    }
    
    if(*p_tls_version == TLS13) {
        if(!client_hello.parsed_extensions.contains(ExtensionType::supported_groups)) {
            throw ssl_error("supported groups are required for TLS 1.3", AlertLevel::fatal, AlertDescription::illegal_parameter);
        }
        if(client_hello.pre_shared_key) {
            if(client_hello.pskmodes.size() == 0) {
                throw ssl_error("preshared_key requires preshared_key_modes extension", AlertLevel::fatal, AlertDescription::handshake_failure);
            }
        }
        client_public_key = choose_client_public_key(client_hello.shared_keys, client_hello.supported_groups);
        if(is_hello_retry()) {
            if(hello_retry_count > 0) {
                throw ssl_error("one hello retry should be sufficient", AlertLevel::fatal, AlertDescription::handshake_failure);
            }
            hello_retry_count++;
        }
    }
    
    CRIME_compression(client_hello);
    alpn = choose_alpn(client_hello.application_layer_protocols);
    m_SNI = choose_server_name(client_hello.server_names);

    if(is_hello_retry()) {
        auto message_hash_record = synthetic_message_hash(*hash_ctor, handshake_message);
        handshake_hasher->update(message_hash_record.m_contents);
    } else {
        handshake_hasher->update(handshake_message);
    }
    
    if(*p_tls_version == TLS13 and !is_hello_retry()) {
        auto [resumption_psk, selected_identity] = get_resumption_psk(handshake_message);
        tls13_early_key_calc(*hash_ctor, tls13_key_schedule, resumption_psk, handshake_hasher->hash());
        selected_preshared_key_id = selected_identity;
    }
}

bool handshake_ctx::is_hello_retry() {
    assert(p_tls_version != nullptr);
    return client_public_key.key.empty() and *p_tls_version == TLS13;
}

tls_record handshake_ctx::server_hello_record() {
    auto hello_record = tls_record(ContentType::Handshake);
    hello_record.m_contents.reserve(128);

    // server random
    m_server_random = make_hello_random(*p_tls_version, is_hello_retry());

    hello_record.write1(HandshakeType::server_hello);
    
    hello_record.start_size_header(3);

    hello_record.write2(TLS12);

    hello_record.write(m_server_random);

    // session_id
    if(middlebox_compatibility()) {
        hello_record.write1(32);
        hello_record.write(client_hello.client_session_id); // session ID
    } else {
        hello_record.write1(0); // session ID
    }
    hello_record.write2(cipher);
    hello_record.write1(0); // no compression

    if(is_hello_retry()) {
        hello_retry_extensions(hello_record);
    } else {
        hello_extensions(hello_record);
    }

    hello_record.end_size_header();

    assert(hello_record.m_contents.size() >= 4);
    assert(handshake_hasher != nullptr);
    
    handshake_hasher->update(hello_record.m_contents);

    if(*p_tls_version == TLS13 and !is_hello_retry()) {
        ustring shared_secret = get_shared_secret(server_private_key_ephem, client_public_key);
        tls13_handshake_key_calc(*hash_ctor, tls13_key_schedule, shared_secret, handshake_hasher->hash());
    }
    return hello_record;
}

tls_record handshake_ctx::server_encrypted_extensions_record() {
    tls_record out(ContentType::Handshake);
    out.write1(HandshakeType::encrypted_extensions);
    out.start_size_header(3);
    out.start_size_header(2);
    if(client_hello.parsed_extensions.contains(ExtensionType::application_layer_protocol_negotiation)) {
        write_alpn_extension(out, alpn);
    }
    out.end_size_header();
    out.end_size_header();
    handshake_hasher->update(out.m_contents);
    return out;
}

tls_record handshake_ctx::server_certificate_record() {
    tls_record certificate_record(ContentType::Handshake);
    certificate_record.write1(HandshakeType::certificate);
    certificate_record.start_size_header(3);
    if(*p_tls_version == TLS13) {
        certificate_record.write1(0);
    }
    certificates_serial(certificate_record, m_SNI, *p_tls_version == TLS13);
    certificate_record.end_size_header();
    handshake_hasher->update(certificate_record.m_contents);
    return certificate_record;
}

[[nodiscard]] tls_record handshake_ctx::server_certificate_verify_record() {
    auto certificate_private = privkey_for_domain(m_SNI);
    auto hash_verify_context = handshake_hasher->hash();

    sha256 ctx;
    ctx.update(ustring(64, 0x20));
    ctx.update(to_unsigned("TLS 1.3, server CertificateVerify"));
    ctx.update(ustring{0});
    ctx.update(hash_verify_context);
    auto hash_out = ctx.hash();

    std::array<uint8_t, 32> signature_digest;
    std::copy(hash_out.begin(), hash_out.end(), signature_digest.begin());
    std::array<uint8_t, 32> csrn;
    randomgen.randgen(csrn);
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));

    tls_record record(ContentType::Handshake);
    record.write1(HandshakeType::certificate_verify);
    record.start_size_header(3);
    record.write2(SignatureScheme::ecdsa_secp256r1_sha256);
    record.start_size_header(2);
    record.write(signature);
    record.end_size_header();
    record.end_size_header();
    handshake_hasher->update(record.m_contents);
    return record;
}

tls_record handshake_ctx::server_handshake_finished13_record() {
    auto server_finished_key = hkdf_expand_label(*hash_ctor, tls13_key_schedule.server_handshake_traffic_secret, "finished", std::string(""), hash_ctor->get_hash_size());
    auto verify_record_hash = handshake_hasher->hash();
    auto verify_data = do_hmac(*hash_ctor, server_finished_key, verify_record_hash);

    tls_record record(ContentType::Handshake);
    record.write1(HandshakeType::finished);
    record.start_size_header(3);
    record.write(verify_data);
    record.end_size_header();

    handshake_hasher->update(record.m_contents);
    tls13_application_key_calc(*hash_ctor, tls13_key_schedule, handshake_hasher->hash());
    return record;
}

void handshake_ctx::client_handshake_finished13_record(const ustring& handshake_message) {
    auto server_finished_hash = handshake_hasher->hash();
    auto client_finished_key = hkdf_expand_label(*hash_ctor, tls13_key_schedule.client_handshake_traffic_secret, "finished", std::string(""), hash_ctor->get_hash_size());
    auto verify_data = do_hmac(*hash_ctor, client_finished_key, server_finished_hash);

    if(verify_data != handshake_message.substr(4)){
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    handshake_hasher->update(handshake_message);
    auto client_finished_hash = handshake_hasher->hash();
    tls13_resumption_key_calc(*hash_ctor, tls13_key_schedule, client_finished_hash);
}

tls_record handshake_ctx::server_key_exchange_record() {
    randomgen.randgen(server_private_key_ephem);
    std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(server_private_key_ephem);
    
    // Record Header
    tls_record record(ContentType::Handshake);

    // Handshake Header
    record.m_contents.reserve(116);
    record.write1(HandshakeType::server_key_exchange);
    record.start_size_header(3);

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
    
    hashctx->update(client_hello.m_client_random);
    hashctx->update(m_server_random);
    hashctx->update(signed_empheral_key);
    
    auto signature_digest_vec = hashctx->hash();
    assert(signature_digest_vec.size() == 32);
    std::array<uint8_t, 32> signature_digest;
    std::copy(signature_digest_vec.cbegin(), signature_digest_vec.cend(), signature_digest.begin());
    
    auto certificate_private = privkey_for_domain(m_SNI);

    // Signature
    std::array<uint8_t, 32> csrn;
    randomgen.randgen(csrn);
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));
    ustring sig_header ({static_cast<uint8_t>(HashAlgorithm::sha256), // Signature Header
        static_cast<uint8_t>(SignatureAlgorithm::ecdsa)});
    
    record.write(signed_empheral_key);
    record.write(sig_header);
    record.start_size_header(2);
    record.write(signature);
    record.end_size_header();

    assert(record.m_contents.size() >= 4);
    record.end_size_header();

    handshake_hasher->update(record.m_contents);
    return record;
}

tls_record handshake_ctx::server_hello_done_record() {
    tls_record record(ContentType::Handshake);
    record.write1(HandshakeType::server_hello_done);
    record.start_size_header(3);
    record.end_size_header();
    handshake_hasher->update(record.m_contents);
    return record;
}

tls_record handshake_ctx::server_handshake_finished12_record() {
    tls_record out(ContentType::Handshake);
    out.write1(HandshakeType::finished);
    out.start_size_header(3);
    
    assert(handshake_hasher);
    auto handshake_hash = handshake_hasher->hash();
    assert(handshake_hash.size() == 32);
    
    ustring server_finished = prf(*hash_ctor, tls12_master_secret, "server finished", handshake_hash, 12);
    
    out.write(server_finished);
    out.end_size_header();
    return out;
}

void handshake_ctx::hello_retry_extensions(tls_record& record) {
    assert(p_tls_version != nullptr);
    assert(*p_tls_version == TLS13);
    assert(client_hello.parsed_extensions.contains(ExtensionType::key_share));
    assert(is_hello_retry());
    record.start_size_header(2);
    write_supported_versions(record, *p_tls_version);
    write_cookie(record);
    write_key_share_request(record, client_public_key.key_type);
    record.end_size_header();
}

void handshake_ctx::hello_extensions(tls_record& record) {
    record.start_size_header(2);
    if(*p_tls_version == TLS13) {
        assert(client_hello.parsed_extensions.contains(ExtensionType::key_share));
        assert(!client_public_key.key.empty());
        auto [ privkey, pubkey_ephem ] = server_keypair(client_public_key.key_type);
        server_private_key_ephem = privkey;
        write_key_share(record, pubkey_ephem);
    }
    if(client_hello.parsed_extensions.contains(ExtensionType::supported_versions) and *p_tls_version == TLS13) {
        write_supported_versions(record, *p_tls_version);
    }
    if(auto it = std::find(client_hello.cipher_su.begin(), client_hello.cipher_su.end(), cipher_suites::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        (it != client_hello.cipher_su.end() or
        client_hello.parsed_extensions.contains(ExtensionType::renegotiation_info)) and *p_tls_version == TLS12)  {
            write_renegotiation_info(record);
    }
    if(client_hello.parsed_extensions.contains(ExtensionType::application_layer_protocol_negotiation) and *p_tls_version == TLS12) {
        write_alpn_extension(record, alpn);
    }
    if(client_hello.parsed_extensions.contains(ExtensionType::heartbeat)) {
        write_heartbeat(record);
    }
    if(client_hello.parsed_extensions.contains(ExtensionType::pre_shared_key)) {
        if(selected_preshared_key_id) {
            for(auto mode : client_hello.pskmodes) {
                if(mode == PskKeyExchangeMode::psk_dhe_ke) {
                    selected_psk_mode = PskKeyExchangeMode::psk_dhe_ke;
                    write_pre_shared_key_extension(record, *selected_preshared_key_id);
                }
            }
        }
    }
    record.end_size_header();
}


ustring handshake_ctx::client_key_exchange_receipt(const ustring& key_exchange) {
    
    static_cast<void>(key_exchange.at(0));
    assert(key_exchange[0] == static_cast<uint8_t>(HandshakeType::client_key_exchange));
    
    const size_t len = try_bigend_read(key_exchange, 1, 3);
    const size_t keylen = try_bigend_read(key_exchange, 4, 1);
    if(len + 4 != key_exchange.size() or len != keylen + 1) [[unlikely]] {
        throw ssl_error("bad key exchange", AlertLevel::fatal, AlertDescription::decode_error);
    }
    
    if(key_exchange.size() < 37) [[unlikely]] {
        throw ssl_error("bad public key", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    client_public_key.key.resize(32);
    client_public_key.key_type = NamedGroup::x25519;
    std::copy(&key_exchange[5], &key_exchange[37], client_public_key.key.begin());
    std::array<uint8_t, 32> client_pub{};
    std::copy_n(client_public_key.key.begin(), 32, client_pub.begin());
    auto premaster_secret = fbw::curve25519::multiply(server_private_key_ephem, client_pub);
    ustring client_hello_str(client_hello.m_client_random.begin(), client_hello.m_client_random.end());
    tls12_master_secret = prf(*hash_ctor, premaster_secret, "master secret", client_hello_str + m_server_random, 48);

    handshake_hasher->update(key_exchange);

    // AES_256_CBC_SHA256 has the largest amount of key material at 128 bytes
    auto key_material = prf(*hash_ctor,  tls12_master_secret, "key expansion", m_server_random + client_hello_str, 128);
    return key_material;
}

void handshake_ctx::client_handshake_finished12_record(const ustring& handshake_message) {
    
    static_cast<void>(handshake_message.at(0));
    if(handshake_message[0] != static_cast<uint8_t>(HandshakeType::finished)) [[unlikely]] {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    const size_t len = try_bigend_read(handshake_message, 1, 3);
    if(len != 12) {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    auto finish = handshake_message.substr(4);
    auto handshake_hash = handshake_hasher->hash();
    ustring expected_finished = prf(*hash_ctor, tls12_master_secret, "client finished", handshake_hash, 12);

    if(expected_finished != finish) [[unlikely]] {
        throw ssl_error("handshake verification failed", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    handshake_hasher->update(handshake_message);
}


bool handshake_ctx::middlebox_compatibility() {
    assert(p_tls_version != nullptr);
    return !client_hello.client_session_id.empty() and (*p_tls_version == TLS13);
}


}
