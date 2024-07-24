//
//  string_utils.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 15/07/2021.
//

#ifndef string_utils_hpp
#define string_utils_hpp

#include "../global.hpp"

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <utility>
#include <bit>

namespace fbw {

// throw HTTP error status codes
class http_error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct http_frame {
    ustring header;
    ustring body;
};


// A pretty timestamp for response headers
[[nodiscard]] std::string timestring(time_t t);

// returns n bytes FIFO from an HTTP stream, and removes those bytes from the stream
// Note that this returns an empty string if there are fewer than n bytes in the stream
// O(N) in the current length of the stream
ustring extract(ustring& bytes, size_t nbytes);


// returns bytes FIFO up to a delimiter from an HTTP stream, and removes those bytes from the stream
// Note that this returns an empty string if the delimiter is not present
// O(N) in the current length of the stream
ustring extract(ustring& bytes, std::string delimiter);


// Headers a series of fields
// Content-Type, Content-Length etc.
// What value does this field take?
[[nodiscard]] std::string get_argument(const ustring& header, std::string field);

// tokenises a request header e.g. {'GET', '/<filename>', "HTTP/1.1" }
[[nodiscard]] std::vector<std::string> get_method(const ustring& header);

// returns the length of the body or its closing delimiter depending on the encoding
[[nodiscard]] std::pair<std::string, size_t> body_size(const ustring& header);

// adds "index", ".html" as necessary and moves to lowercase
// to convert an HTTP request file to a filesystem file name
std::string fix_filename(std::string filename);

std::string make_server_name();

[[nodiscard]] std::vector<std::pair<ssize_t, ssize_t>> parse_range_header(const std::string& range_header);


} // namespace fbw
#endif // string_utils_hpp
