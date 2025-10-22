//
//  key_derivation.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/07/2024.
//

#include "key_derivation.hpp"
#include "one_way/hash_base.hpp"

namespace fbw {

std::vector<uint8_t> compute_binder(const hash_base& base, const std::vector<uint8_t>& resumption_psk, std::span<const uint8_t> binder_hash) {
    auto empty_hash = do_hash(base, std::vector<uint8_t>{});
    std::vector<uint8_t> const early_secret = hkdf_extract(base, std::vector<uint8_t>{}, resumption_psk);
    std::vector<uint8_t> const binder_key = hkdf_expand_label(base, early_secret, "res binder", empty_hash, base.get_hash_size());
    auto expanded_computed_binder = hkdf_expand_label(base, binder_key, "finished", std::vector<uint8_t>{}, 32);
    auto computed_binder = hkdf_extract(base, expanded_computed_binder, binder_hash);
    return computed_binder;
}

void tls13_early_key_calc(const hash_base& base, key_schedule& key_sch, const std::vector<uint8_t>& psk, const std::vector<uint8_t>& client_hello_hash) {
    auto empty_hash = do_hash(base, std::vector<uint8_t>{});
    key_sch.early_secret = hkdf_extract(base, std::vector<uint8_t>{}, psk);
    key_sch.resumption_binder_key = hkdf_expand_label(base, key_sch.early_secret, "res binder", empty_hash, base.get_hash_size());
    key_sch.external_binder_key = hkdf_expand_label(base, key_sch.early_secret, "ext binder", empty_hash, base.get_hash_size());
    key_sch.client_early_traffic_secret = hkdf_expand_label(base, key_sch.early_secret, "c e traffic", client_hello_hash, base.get_hash_size());
    key_sch.early_exporter_master_secret = hkdf_expand_label(base, key_sch.early_secret, "e exp master", client_hello_hash, base.get_hash_size());

    key_sch.early_derived_secret = hkdf_expand_label(base, key_sch.early_secret, "derived", empty_hash, base.get_hash_size());
}

void tls13_handshake_key_calc(const hash_base& base, key_schedule& key_sch, const std::vector<uint8_t>& ecdh, const std::vector<uint8_t>& server_hello_hash) {
    auto empty_hash = do_hash(base, std::vector<uint8_t>{});
    
    key_sch.handshake_secret = hkdf_extract(base, key_sch.early_derived_secret, ecdh);
    key_sch.server_handshake_traffic_secret = hkdf_expand_label(base, key_sch.handshake_secret, "s hs traffic", server_hello_hash, base.get_hash_size());
    key_sch.client_handshake_traffic_secret = hkdf_expand_label(base, key_sch.handshake_secret, "c hs traffic", server_hello_hash, base.get_hash_size());

    key_sch.handshake_derived_secret = hkdf_expand_label(base, key_sch.handshake_secret, "derived", empty_hash, base.get_hash_size());
}

void tls13_application_key_calc(const hash_base& base, key_schedule& key_sch, const std::vector<uint8_t>& server_finished_hash) {
    const auto empty_hash = do_hash(base, std::vector<uint8_t>{});
    const auto zero_key = std::vector<uint8_t>(base.get_hash_size(), 0);

    key_sch.master_secret = hkdf_extract(base, key_sch.handshake_derived_secret, zero_key);
    key_sch.server_application_traffic_secret = hkdf_expand_label(base, key_sch.master_secret, "s ap traffic", server_finished_hash, base.get_hash_size());
    key_sch.client_application_traffic_secret = hkdf_expand_label(base, key_sch.master_secret, "c ap traffic", server_finished_hash, base.get_hash_size());
    
    key_sch.exporter_master_secret = hkdf_expand_label(base, key_sch.master_secret, "exp master", server_finished_hash, base.get_hash_size());
}

void tls13_resumption_key_calc(const hash_base& base, key_schedule& key_sch, const std::vector<uint8_t>& client_finished_hash) {
    key_sch.resumption_master_secret = hkdf_expand_label(base, key_sch.master_secret, "res master", client_finished_hash, base.get_hash_size());
}

} //namespace fbw

