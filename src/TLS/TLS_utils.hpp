//
//  TLS_utils.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//


#ifndef tls_utils_hpp
#define tls_utils_hpp


#include "Cryptography/one_way/hash_base.hpp"
#include "Cryptography/cipher/block_chain.hpp"
#include "../global.hpp"
#include "Cryptography/one_way/sha2.hpp"

#include "TLS_enums.hpp"
#include "../TCP/tcp_stream.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/stream_base.hpp"

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>

namespace fbw {

void certificates_serial(tls_record& record, std::string domain, bool use_tls13);
std::optional<tls_record> try_extract_record(ustring& input);

} // namespace


#endif // tls_utils_hpp