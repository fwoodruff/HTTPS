//
//  key_derivation.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/07/2024.
//

#include "key_derivation.hpp"
#include "one_way/hash_base.hpp"

namespace fbw {

// get the binder key for this preshared key but don't commit to the key schedule yet
ustring candidate_binder_key(const hash_base& base, ustring psk) {
    ustring early_secret = hkdf_extract(base, ustring{}, psk);
    auto empty_hash = do_hash(base, ustring{});
    ustring resumption_binder_key = hkdf_expand_label(base, early_secret, "res binder", empty_hash, base.get_hash_size());
    return resumption_binder_key;
}

void tls13_early_key_calc(const hash_base& base, key_schedule& key_sch, ustring psk, ustring client_hello_hash) {
    auto empty_hash = do_hash(base, ustring{});

    key_sch.early_secret = hkdf_extract(base, ustring{}, psk);
    key_sch.resumption_binder_key = hkdf_expand_label(base, key_sch.early_secret, "res binder", empty_hash, base.get_hash_size());
    key_sch.external_binder_key = hkdf_expand_label(base, key_sch.early_secret, "ext binder", empty_hash, base.get_hash_size());
    key_sch.client_early_traffic_secret = hkdf_expand_label(base, key_sch.early_secret, "c e traffic", client_hello_hash, base.get_hash_size());
    key_sch.early_exporter_master_secret = hkdf_expand_label(base, key_sch.early_secret, "e exp master", client_hello_hash, base.get_hash_size());

    key_sch.early_derived_secret = hkdf_expand_label(base, key_sch.early_secret, "derived", empty_hash, base.get_hash_size());
}

void tls13_handshake_key_calc(const hash_base& base, key_schedule& key_sch, ustring ecdh, ustring server_hello_hash) {
    auto empty_hash = do_hash(base, ustring{});
    
    key_sch.handshake_secret = hkdf_extract(base, key_sch.early_derived_secret, ecdh);
    key_sch.server_handshake_traffic_secret = hkdf_expand_label(base, key_sch.handshake_secret, "s hs traffic", server_hello_hash, base.get_hash_size());
    key_sch.client_handshake_traffic_secret = hkdf_expand_label(base, key_sch.handshake_secret, "c hs traffic", server_hello_hash, base.get_hash_size());

    key_sch.handshake_derived_secret = hkdf_expand_label(base, key_sch.handshake_secret, "derived", empty_hash, base.get_hash_size());
}

void tls13_application_key_calc(const hash_base& base, key_schedule& key_sch, ustring server_finished_hash) {
    const auto empty_hash = do_hash(base, ustring{});
    const auto zero_key = ustring(base.get_hash_size(), 0);

    key_sch.master_secret = hkdf_extract(base, key_sch.handshake_derived_secret, zero_key);
    key_sch.server_application_traffic_secret = hkdf_expand_label(base, key_sch.master_secret, "s ap traffic", server_finished_hash, base.get_hash_size());
    key_sch.client_application_traffic_secret = hkdf_expand_label(base, key_sch.master_secret, "c ap traffic", server_finished_hash, base.get_hash_size());
    
    key_sch.exporter_master_secret = hkdf_expand_label(base, key_sch.master_secret, "exp master", server_finished_hash, base.get_hash_size());
}

void tls13_resumption_key_calc(const hash_base& base, key_schedule& key_sch, ustring client_finished_hash) {
    key_sch.resumption_master_secret = hkdf_expand_label(base, key_sch.master_secret, "res master", client_finished_hash, base.get_hash_size());
}

} //namespace fbw

