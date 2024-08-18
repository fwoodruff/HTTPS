//
//  TLS_utils.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//

#include "TLS_utils.hpp"

#include "../global.hpp"
#include "PEMextract.hpp"

namespace fbw {

void certificates_serial(tls_record& record, std::string domain, bool tls_13) {
    record.start_size_header(3);
    std::vector<ustring> certs;
    try {
        certs = der_cert_for_domain(domain);
    } catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
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



}