//
//  TLS_utils.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//

#include "TLS_utils.hpp"

#include "../global.hpp"
#include "PEMextract.hpp"

#include <print>

namespace fbw {

void certificates_serial(tls_record& record, std::string domain, bool tls_13) {
    record.start_size_header(3);
    std::vector<ustring> certs;
    try {
        certs = der_cert_for_domain(domain);
    } catch(std::exception& e) {
        std::println(std::cerr, "{}", e.what());
        throw e;
    }
    for (const auto& cert : certs) {
        record.start_size_header(3);
        record.write(cert);
        record.end_size_header();
        if(tls_13) { // certificate extensions
            record.start_size_header(2);
            record.end_size_header();
        }
    }
    record.end_size_header();
}

std::optional<tls_record> try_extract_record(ustring& input) {
    if (input.size() < TLS_HEADER_SIZE) {
        return std::nullopt;
    }
    tls_record out(static_cast<ContentType>(input[0]), input[1], input[2] );

    size_t record_size = try_bigend_read(input, 3, 2);
    if(record_size > TLS_RECORD_SIZE + TLS_EXPANSION_MAX) [[unlikely]] {
        throw ssl_error("record header size too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    if(input.size() < record_size + TLS_HEADER_SIZE) [[unlikely]] {
        return std::nullopt;
    }
    out.m_contents = input.substr(TLS_HEADER_SIZE, record_size);
    input = input.substr(TLS_HEADER_SIZE + record_size);
    return out;
}

}