//
//  HTTP.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#ifndef http_hpp
#define http_hpp

#include "../../IP/tcp_stream.hpp"



#include <string>
#include <memory>
#include <vector>

namespace fbw {

ssize_t get_file_size(std::filesystem::path filename);
std::string moved_301();

} // namespace fbw
 
#endif // http_hpp
