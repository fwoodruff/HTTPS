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
#include <deque>

namespace fbw {

constexpr ssize_t RANGE_SUGGESTED_SIZE = 0x20d1ac;

// List of HTTP request types
// Used to distinguish between malformed requests and unsupported requests
const std::unordered_set<std::string> verbs {"GET", "HEAD", "POST", "PUT",
                                                "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

const std::unordered_map<int, std::string> http_code_map {
    {100, "Continue"},
    {101, "Switching Protocols"},
    {102, "Processing"},
    {103, "Early Hints"},
    {110, "Response is Stale"},
    {111, "Revalidation Failed"},
    {112, "Disconnected Operation"},
    {113, "Heuristic Expiration"},
    {199, "Miscellaneous Warning"},
    {200, "OK"},
    {201, "Created"},
    {202, "Accepted"},
    {203, "Non-Authoritative Information"},
    {204, "No Content"},
    {205, "Reset Content"},
    {206, "Partial Content"},
    {207, "Multi-Status"},
    {208, "Already Reported"},
    {214, "Transformation Applied"},
    {218, "This is fine"},
    {226, "IM Used"},
    {299, "Miscellaneous Persistent Warning"},
    {300, "Multiple Choices"},
    {301, "Moved Permanently"},
    {302, "Found"},
    {303, "See Other"},
    {304, "Not Modified"},
    {305, "Use Proxy"},
    {306, "Switch Proxy"},
    {307, "Temporary Redirect"},
    {308, "Permanent Redirect"},
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {402, "Payment Required"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {405, "Method Not Allowed"},
    {406, "Not Acceptable"},
    {407, "Proxy Authentication Required"},
    {408, "Request Timeout"},
    {409, "Conflict"},
    {410, "Gone"},
    {411, "Length Required"},
    {412, "Precondition Failed"},
    {413, "Payload Too Large"},
    {414, "URI Too Long"},
    {415, "Unsupported Media Type"},
    {416, "Range Not Satisfiable"},
    {417, "Expectation Failed"},
    {418, "I'm a teapot"},
    {419, "Page Expired"},
    {420, "Method Failure"},
    {421, "Misdirected Request"},
    {422, "Unprocessable Content"},
    {423, "Locked"},
    {424, "Failed Dependency"},
    {425, "Too Early"},
    {426, "Upgrade Required"},
    {428, "Precondition Required"},
    {429, "Too Many Requests"},
    {430, "Request Header Fields Too Large"},
    {431, "Request Header Fields Too Large"},
    {440, "Login Time-out"},
    {444, "No Response"},
    {449, "Retry With"},
    {450, "Blocked by Windows Parental Controls"},
    {451, "Unavailable For Legal Reasons"},
    {494, "Request header too large"},
    {495, "SSL Certificate Error"},
    {496, "SSL Certificate Required"},
    {497, "HTTP Request Sent to HTTPS Port"},
    {498, "Invalid Token"},
    {499, "Token Required"},
    {500, "Internal Server Error"},
    {501, "Not Implemented"},
    {502, "Bad Gateway"},
    {503, "Service Unavailable"},
    {504, "Gateway Timeout"},
    {505, "HTTP Version Not Supported"},
    {506, "Variant Also Negotiates"},
    {507, "Insufficient Storage"},
    {508, "Loop Detected"},
    {509, "Bandwidth Limit Exceeded"},
    {510, "Not Extended"},
    {511, "Network Authentication Required"},
    {520, "Web Server Returned an Unknown Error"},
    {521, "Web Server Is Down"},
    {522, "Connection Timed Out"},
    {523, "Origin Is Unreachable"},
    {524, "A Timeout Occurred"},
    {525, "SSL Handshake Failed"},
    {526, "Invalid SSL Certificate"},
    {527, "Railgun Error"},
    {529, "Site is overloaded"},
    {530, "Site is frozen"},
    {540, "Temporarily Disabled"},
    {561, "Unauthorized"},
    {598, "Network read timeout error"},
    {599, "Network Connect Timeout Error"},
    {783, "Unexpected Token"},
    {999, "Non-standard"}
};

// throw HTTP error status codes
class http_error : public std::runtime_error {
public:
    int m_http_code;
    http_error(int http_code, const std::string& what_arg) :
        std::runtime_error(what_arg), m_http_code(http_code) {}
};

struct http_header {
    std::string protocol;
    std::string verb;
    std::string resource;
    std::unordered_map<std::string, std::string> headers;
};

struct http_frame {
    http_header header;
    std::vector<uint8_t> body;
};

// A pretty timestamp for response headers
[[nodiscard]] std::string timestring(time_t t);

// returns n bytes FIFO from an HTTP stream, and removes those bytes from the stream
// Note that this returns an empty string if there are fewer than n bytes in the stream
// O(N) in the current length of the stream
std::vector<uint8_t> extract(std::deque<uint8_t>& bytes, size_t nbytes);

// returns bytes FIFO up to a delimiter from an HTTP stream, and removes those bytes from the stream
// Note that this returns an empty string if the delimiter is not present
// O(N) in the current length of the stream
std::vector<uint8_t> extract(std::deque<uint8_t>& bytes, std::string delimiter);

// adds "index", ".html" as necessary and moves to lowercase
// to convert an HTTP request file to a filesystem file name
std::string fix_filename(std::string filename);

std::string make_server_name();

[[nodiscard]] std::vector<std::pair<ssize_t, ssize_t>> parse_range_header(const std::string& range_header);

[[nodiscard]] std::vector<uint8_t> make_header(std::string status, std::unordered_map<std::string, std::string> header);

[[nodiscard]] std::pair<ssize_t, ssize_t> get_range_bounds(ssize_t file_size, std::pair<ssize_t, ssize_t>& range);

[[nodiscard]] std::string error_to_html(int status, std::string message);

[[nodiscard]] std::vector<std::string> split(const std::string& line, const std::string& delim);

[[nodiscard]] std::string trim(std::string str);

[[nodiscard]] http_header parse_http_headers(const std::string& header_str);

void parse_tlds(const std::string& tld_filename);

bool is_tld(std::string domain);

char asciitolower(char in);

std::string to_lower(std::string s);

char asciitoupper(char in);

std::string to_upper(std::string s);


std::string parse_domain(std::string hostname);
} // namespace fbw
#endif // string_utils_hpp
