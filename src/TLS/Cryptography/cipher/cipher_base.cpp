//
//  cipher_base.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef cipher_base_hpp
#define cipher_base_hpp

#include "../../../global.hpp"
#include "../../TLS_utils.hpp"
#include "../key_derivation.hpp"

#include <cstdio>

namespace fbw {

tls_record wrap13(tls_record record) {
    if(record.get_type() == ContentType::ChangeCipherSpec) {
        return record;
    }
    record.m_contents.push_back(static_cast<uint8_t>(record.get_type()));
    record.m_type = ContentType::Application;
    return record;
}

tls_record unwrap13(tls_record record) {
    assert(record.m_contents.size() > 1);
    while(record.m_contents.size() > 1 and record.m_contents.back() == 0) {
        record.m_contents.pop_back();
    }
    record.m_type = static_cast<ContentType>(record.m_contents.back());
    record.m_contents.pop_back();
    return record;
}

} // namespace fbw


#endif // cipher_base_hpp
