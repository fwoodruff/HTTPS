//
//  string_utils.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 15/07/2021.
//

#ifndef string_utils_hpp
#define string_utils_hpp

#include "../../global.hpp"

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <utility>
#include <bit>
#include <unordered_set>
#include <unordered_map>

namespace fbw {

constexpr ssize_t RANGE_SUGGESTED_SIZE = 0x20d1ac;

// List of HTTP request types
// Used to distinguish between malformed requests and unsupported requests
const std::unordered_set<std::string> verbs {"GET", "HEAD", "POST", "PUT",
                                                "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

// throw HTTP error status codes
class http_error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct http_header {
    std::string protocol;
    std::string verb;
    std::string resource;
    std::unordered_map<std::string, std::string> headers;
};

struct http_frame {
    http_header header;
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

// adds "index", ".html" as necessary and moves to lowercase
// to convert an HTTP request file to a filesystem file name
std::string fix_filename(std::string filename);

std::string make_server_name();

[[nodiscard]] std::vector<std::pair<ssize_t, ssize_t>> parse_range_header(const std::string& range_header);

[[nodiscard]] ustring make_header(std::string status, std::unordered_map<std::string, std::string> header);

[[nodiscard]] std::pair<ssize_t, ssize_t> get_range_bounds(ssize_t file_size, std::pair<ssize_t, ssize_t>& range);

[[nodiscard]] std::string error_to_html(std::string error);

[[nodiscard]] std::vector<std::string> split(const std::string& line, const std::string& delim);

[[nodiscard]] std::string trim(std::string str);

[[nodiscard]] http_header parse_http_headers(const std::string& header_str);

void parse_tlds(const std::string& tld_filename);

bool is_tld(std::string domain);


std::string parse_domain(std::string hostname);
} // namespace fbw
#endif // string_utils_hpp
