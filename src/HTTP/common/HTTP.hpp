//
//  HTTP.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#ifndef http_hpp
#define http_hpp

#include "../../TCP/tcp_stream.hpp"
#include "../../Runtime/task.hpp"

#include <string>
#include <memory>
#include <vector>
#include <deque>
#include <optional>

namespace fbw {

ssize_t get_file_size(std::filesystem::path filename);
std::string moved_301();

// Read one line from a stream, buffering into buf.
// Returns the line without the trailing CRLF, or nullopt on stream close.
task<std::optional<std::string>> read_http_line(stream& s, std::deque<uint8_t>& buf);

} // namespace fbw
 
#endif // http_hpp
