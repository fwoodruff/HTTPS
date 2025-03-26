//
//  tls_engine.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 25/03/2025.
//

#include "protocol.hpp"

#include "Cryptography/assymetric/x25519.hpp"
#include "Cryptography/one_way/sha2.hpp"
#include "Cryptography/assymetric/secp256r1.hpp"
#include "PEMextract.hpp"
#include "TLS_enums.hpp"
#include "../global.hpp"
#include "Cryptography/one_way/keccak.hpp"
#include "Cryptography/cipher/block_chain.hpp"
#include "Cryptography/cipher/galois_counter.hpp"
#include "Cryptography/cipher/chacha20poly1305.hpp"
#include "../TCP/tcp_stream.hpp"
#include "Cryptography/key_derivation.hpp"
#include "TLS_utils.hpp"
#include "session_ticket.hpp"
#include "tls_engine.hpp"

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <utility>
#include <thread>

#include <queue>

namespace fbw {

using enum ContentType;

// if the last record is going to be really small, just add that data to the penultimate record
bool squeeze_last_chunk_imp(ssize_t additional_data_len) {
    return  size_t(additional_data_len) < WRITE_RECORD_SIZE and 
            additional_data_len != 0 and 
            additional_data_len + WRITE_RECORD_SIZE + 50 < TLS_RECORD_SIZE and
            size_t(additional_data_len) * 3 < WRITE_RECORD_SIZE * 2;
}

void tls_engine::flush_sync(std::vector<packet_timed>& output) {
    if(encrypt_send.size() >= 2) {
        if(squeeze_last_chunk_imp(encrypt_send.back().m_contents.size())) {
            auto back = std::move(encrypt_send.back());
            encrypt_send.pop_back();
            encrypt_send.back().m_contents.append(back.m_contents);
        }
    }
    while(!encrypt_send.empty()) {
        auto& record = encrypt_send.front();
        if(record.m_contents.empty()) {
            encrypt_send.pop_front();
            continue;
        }
        write_record_sync(output, std::move(record), project_options.session_timeout);
        encrypt_send.pop_front();
    }
}

void tls_engine::write_record_sync(std::vector<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout) {
    if(server_cipher_spec && record.get_type() != ChangeCipherSpec) {
        assert(cipher_context);
        record = cipher_context->encrypt(record);
    }
    output.push_back({record.serialise(), timeout});
}

}
