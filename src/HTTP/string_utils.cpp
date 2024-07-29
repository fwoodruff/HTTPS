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

char asciitolower(char in) {
    if (in <= 'Z' && in >= 'A')
        return in - ('Z' - 'z');
    return in;
}

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



std::vector<std::string> split(const std::string& line, const std::string& delim) {
    std::vector<std::string> out;
    size_t start = 0;
    size_t end = 0;
    while ((end = line.find(delim, start)) != std::string::npos) {
        if (start != end) {
            out.push_back(line.substr(start, end - start));
        }
        start = end + delim.size(); 
    }
    if (start != line.size()) {
        out.push_back(line.substr(start));
    }
    
    return out;
}

std::string trim(std::string str) {
    auto start = str.find_first_not_of(" \t\r\n");
    auto end = str.find_last_not_of(" \t\r\n");
    if(start == std::string::npos or end == std::string::npos) {
        str = "";
    }
    return str.substr(start, end - start + 1);
}

http_header parse_http_headers(const std::string& header_str) {
    http_header headers;
    size_t start = 0;
    size_t end = 0;
    const std::string delim = "\r\n";

    end = header_str.find(delim, start);
    if (end != std::string::npos) {
        auto line = header_str.substr(start, end - start); 
        auto objs = split(line, " ");
        start = end + delim.size();
        if(objs.size() != 3) {
            throw http_error("400 Bad Request");
        }
        headers.verb = trim(objs[0]);
        headers.resource = trim(objs[1]);
        headers.protocol = trim(objs[2]);
    }
    while ((end = header_str.find(delim, start)) != std::string::npos) {
        auto line = header_str.substr(start, end - start);
        start = end + delim.size(); 
        const size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            auto key = trim(line.substr(0, colon_pos));
            auto value = trim(line.substr(colon_pos + 1));
            std::transform(key.begin(), key.end(), key.begin(), asciitolower);
            std::transform(value.begin(), value.end(), value.begin(), asciitolower);
            headers.headers[key] = value;
        }
    }
    return headers;
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

std::unordered_set<std::string> known_tlds;



void parse_tlds(const std::string& tld_filename) {
    std::ifstream tld_file(tld_filename);
    if (!tld_file.is_open()) {
        throw std::runtime_error("TLD file not found\n");
    }
    std::string tld;
    while (std::getline(tld_file, tld)) {
        remove_whitespace(tld);
        if (tld.empty() || tld[0] == '#') {
            continue; // skip comments
        }
        std::transform(tld.begin(), tld.end(), tld.begin(), asciitolower);
        known_tlds.insert(tld);
    }
}

bool is_tld(std::string domain) {
    return known_tlds.find(domain) != known_tlds.end();
}

std::string parse_domain(std::string hostname) {
    std::transform(hostname.begin(), hostname.end(), hostname.begin(), asciitolower);
    if(hostname == "localhost" or hostname == "test" or hostname == "invalid") {
        return hostname;
    }
    auto hostname_parts = split(hostname, ".");
    if(hostname_parts.empty()) {
        return {};
    }
    std::string top_level_domain = hostname_parts.back();
    hostname_parts.pop_back();
    while(!hostname_parts.empty()) {
        if(is_tld(hostname_parts.back())) {
            top_level_domain = hostname_parts.back() + "." + top_level_domain;
            hostname_parts.pop_back();
        } else {
            break;
        }
    }
    if(hostname_parts.empty()) {
        return {};
    }
    return hostname_parts.back() + "." + top_level_domain;
}

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
        size_t end = range_header.find(',', pos);
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
    size_t content_size = 0;
    for(auto [k, v] : header) {
        if(k == "Content-Length") {
            content_size = std::stol(v);
        }
        oss << k << ": " << v << "\r\n";
    }
    std::string head = oss.str();
    const std::string pad = "paddingpadding";
    size_t padding_length = ((content_size + head.size()) % (pad.size() - 1)) + 1;
    head += "X-Padding: " + std::string(pad.c_str(), padding_length);
    head += "\r\n\r\n";

    return to_unsigned(head);
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
