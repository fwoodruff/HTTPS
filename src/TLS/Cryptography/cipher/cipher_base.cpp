//
//  cipher_base.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef cipher_base_hpp
#define cipher_base_hpp

#include "../../../global.hpp"
#include "../../TLS_enums.hpp"
#include "../key_derivation.hpp"

#include <cstdio>

namespace fbw {

tls_record wrap13(tls_record record) {
    if(record.get_type() == static_cast<uint8_t>(ContentType::ChangeCipherSpec)) {
        return record;
    }
    record.m_contents.push_back(record.get_type());
    record.m_type = static_cast<uint8_t>(ContentType::Application);
    return record;
}

tls_record unwrap13(tls_record record) {
    while(record.m_contents.size() > 1 and record.m_contents.back() == 0) {
        record.m_contents.pop_back();
    }
    record.m_type = record.m_contents.back();
    record.m_contents.pop_back();
    return record;
}

} // namespace fbw


#endif // cipher_base_hpp
