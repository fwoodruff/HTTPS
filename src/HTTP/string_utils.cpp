//
//  string_utils.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 15/07/2021.
//

#include "string_utils.hpp"
#include "../TLS/Cryptography/one_way/keccak.hpp"

#include <sys/stat.h>
#include "../global.hpp"

#include <string>
#include <ctime>
#include <iomanip>
#include <unordered_set>
#include <sstream>
#include <cassert>
#include <iostream>
#include <algorithm>

namespace fbw {


// convert current time for string
// used in response header
std::string timestring(time_t t) {
    char buf[48];
    std::tm* tm_ptr = std::gmtime(&t);
    assert(tm_ptr != nullptr);
    const std::tm tm = *tm_ptr;
    auto err = std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", &tm);
    assert(err != 0);
    const std::string out(buf);
    return out;
}

// helps parse HTTP streams
ustring extract(ustring& bytes, std::string delimiter) {
    if(delimiter == "") return {};
    const size_t n = bytes.find(to_unsigned(delimiter));
    if (n == std::string::npos) {
        return {};
    }
    ustring ret = bytes.substr(0, n + delimiter.size());
    bytes = bytes.substr(n + delimiter.size());
    return ret;
}

ustring extract(ustring& bytes, size_t nbytes) {
    if(nbytes == 0) return {};
    const auto n = bytes.size();
    if(n < nbytes) {
        return {};
    }
    const ustring ret = bytes.substr(0, n);
    bytes = bytes.substr(n);
    return ret;
}

// List of HTTP request types
// Used to distinguish between malformed requests and unsupported requests
const static std::unordered_set<std::string> verbs {"GET", "HEAD", "POST", "PUT",
                                                "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

// uses the header to find the length of the HTTP body
// the return tpe is a length or a delimiter
std::pair<std::string, size_t> body_size(const ustring& header) {
    assert(header.find(to_unsigned("\r\n\r\n")) != std::string::npos);
    
    const auto method = get_method(header);
    if (method.empty() or (verbs.find(method[0]) == verbs.end())) {
        throw http_error("400 Bad Request");
    }
    if(method[0] == "GET") {
        return {std::string(), 0};
    } else if (method[0] == "POST") {
        const std::string content = fbw::get_argument(header, "Content-Type");
        if (content == "") {
            throw http_error("400 Bad Request");
        }
        const std::string multipart = "multipart/form-data;boundary=\"";
        
        if(content == "application/x-www-form-urlencoded") {
            const std::string arg = fbw::get_argument(header, "Content-Length");
            if(arg == "") {
                throw http_error("411 Length Required");
            }
            try {
                return {std::string(), std::stoi(arg) };
            } catch(const std::invalid_argument& e) {
                throw http_error("400 Bad Request");
            }
        } else if (content.size() > multipart.size() and content.substr(0, multipart.size()) == multipart) {
            const auto n = content.find("\r\n");
            assert(n != std::string::npos);
            std::string delimiter = content.substr(multipart.size(), n);
            if (delimiter=="") {
                throw http_error("400 Bad Request");
            }
            delimiter = delimiter.insert(0,"--");
            delimiter = delimiter.append("--");
            return {delimiter, 0};
        } else {
            throw http_error("501 Not Implemented");
        }
    } else {
        throw http_error("405 Method Not Allowed");
    }
    assert(false);
}

// Treats the HTTP header as a key-value map.
// Used for finding the Content-Type, Content-Length etc.
std::string get_argument(const ustring& header, std::string field) {
    assert(header.find(to_unsigned("\r\n\r\n")) != std::string::npos);
    const static std::string endline = "\r\n";
    const static std::string colon = ": ";
    assert(field.max_size() > field.size() + endline.size()+ colon.size());
    field.insert(0,endline);
    field.append(colon);
    const auto n = header.find(to_unsigned(field));
    if(n == std::string::npos) {
        return {};
    }
    const auto st = n + field.size();
    const auto q = header.find(to_unsigned(endline),st);
    if(q == std::string::npos) {
        return {};
    }
    return to_signed(header.substr(st, q-st));
}

// Tokenises a request header e.g. {'GET', '/<filename>', "HTTP/1.1" }
std::vector<std::string> get_method(const ustring& header) {
    const std::string delimiter = " ";
    const std::string endline = "\r\n";
    std::vector<std::string> out;
    const auto line_length = header.find(to_unsigned(endline));
    assert(line_length != std::string::npos);
    size_t distance = 0;
    while(true) {
        const auto n = header.find(to_unsigned(delimiter), distance);

        if (n == std::string::npos or n >= line_length) {
            assert (distance <= line_length);
            const std::string ntoken = to_signed(header.substr(distance, line_length - distance));
            if(ntoken != "") {
                out.push_back(std::move(ntoken));
            }
            break;
        }
        const std::string token = to_signed(header.substr(distance, n - distance));
        if(token != "") {
            out.push_back(std::move(token));
        }
        distance = n + delimiter.size();
    }
    return out;
}

// freddiewoodruff.co.uk implicitly refers to freddiewoodruff.co.uk/index
// which implicitly refers to either freddiewoodruff.co.uk/index.html or
// freddiewoodruff.co.uk/index.php and we need the full form to look up
// the file name locally at the server
std::string fix_filename(std::string filename) {
    if( filename == "/") {
        return "/index.html";
    }
    std::transform(filename.begin(), filename.end(), filename.begin(),
        [](unsigned char c){ return std::tolower(c); });
    if(filename.find(".") == std::string::npos) {
        filename.append(".html");
    }
    return filename;
}

void shuffle(std::array<uint8_t, 32>& state) {
    for(int i = 0; i < 3; i++) {
        state[4] = ~(state[4] & 0x7a);
        for(int j = 0; j < 32; j++) {
            state[j] += (state[(j+10)%32] << 4) * (state[(j+7)%32] >> 1);
            state[j] ^= state[j] >> 3;
        }
    }
}


std::vector<std::string> operating_systems {
    "(5G Vaccine Mast Tower)",
    "(Not an OS, just some guy waving a magnet)",
    "(The Cloud)",
    "(Wandows 3000)",
    "(MS-DOS 4.0)",
    "(Windows Vista)",
    "(Atari DOS)",
    "(iPadOS)",
    "(RISC OS)",
    "(XTS-400)",
    "(Apple Pascal)",
    "(Acorn MOS) (BBC Micro)",
    "(Acorn MOS) (Acorn Electron)",
    "(iOS)",
    "(Harmony OS)",
    "(Intel) (ISIS)",
    "(Vulcan O/S)",
    "(INTEGRITY-178B)",
    "(MSP-EX)",
    "(PDP-10) (TENEX)",
    "(PDP-10) (TOPS-20)",
    "(ENIAC)",
    "(TempleOS)",
    "(Collapse OS)",
    "(AROS) (Commadore)",
    "(Red Star OS 3.0)",
    "(Visopsys)"
    "(HeartOS) (DDC-I)"
};

std::string make_server_name() {
    std::array<uint8_t, 2> random_bytes;
    randomgen.randgen(random_bytes);
    std::string server_name = "FredPi/0.1 " ;
    if(random_bytes[0] > 22) {
        server_name+= "(Unix) (Raspbian/Linux)";
    } else {
        server_name += operating_systems[random_bytes[1] % operating_systems.size()];
    }
    return server_name;
}

std::vector<std::pair<ssize_t, ssize_t>> parse_range_header(const std::string& range_header) {
    std::string prefix = "bytes=";
    if(range_header.substr(0, prefix.size()) != prefix) {
        return {};
    }
    ssize_t pos = prefix.size();
    std::vector<std::pair<ssize_t, ssize_t>> out;
    while(true) {
        ssize_t end = range_header.find(',', pos);
        std::string range = range_header.substr(pos, end - pos);
        remove_whitespace(range);
        ssize_t mid = range.find("-");
        auto first = range.substr(0, mid);
        auto second = range.substr(mid + 1);
        if(first == "" and second == "") {
            return {};
        }
        out.push_back({first == "" ? -1 : std::stoi(first), second == "" ? -1 : std::stoi(second)});
        if(end == std::string::npos) {
            break;
        }
        pos = end + 1;
    }
    return out;
}

ustring make_header(std::string status, std::unordered_map<std::string, std::string> header) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << "\r\n";

    for(auto [k, v] : header) {
        oss << k << ": " << v << "\r\n";
    }
    oss << "\r\n";
    return to_unsigned(oss.str());
}

std::pair<ssize_t, ssize_t> get_range_bounds(ssize_t file_size, std::pair<ssize_t, ssize_t>& range) {
    ssize_t begin;
    ssize_t end;
    if(range.first == -1) {
        begin = file_size - range.second;
        end = file_size;
        range.first = begin;
        range.second = end - 1;
    } else if(range.second == -1) {
        begin = range.first;
        end = std::min(ssize_t(file_size), range.first + RANGE_SUGGESTED_SIZE);
        range.second = end - 1;
    } else {
        begin = range.first;
        end = range.second + 1;
    }

    if (range.first > range.second or range.second >= file_size) {
        throw http_error("416 Requested Range Not Satisfiable");
    }
    assert(end > begin);
    return {begin, end};
}

std::string error_to_html(std::string error) {
    std::ostringstream oss;
    oss << "<!DOCTYPE html>\n"
        << "<html>\n"
        << "<head><title>\n" << error << "</title></head>\n"
        << "\t<body><h1>\n" << error << "</h1></body>\n" 
        << "</html>";
    return oss.str();
}


} // namespace fbw
