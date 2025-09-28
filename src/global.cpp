//
//  global.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 13/12/2021.
//

#include "global.hpp"

#include <string>
#include <fstream>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <unistd.h>
#include <vector>
#include <limits.h>

#include <iomanip>
#include <ctime>
#include <format>

#include <filesystem>

namespace fbw {

void remove_whitespace(std::string& str) {
    std::erase_if(str, ::isspace);
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


options project_options;

std::filesystem::path relative_to(std::filesystem::path query_path, std::filesystem::path relative_to_this) {
    auto abs_path = std::filesystem::absolute(relative_to_this).lexically_normal();
    if(query_path.is_relative()) {
        query_path = abs_path.parent_path() / query_path;
        query_path = std::filesystem::relative(query_path, std::filesystem::current_path());
    }
    return query_path.lexically_normal();
}

void init_options(std::filesystem::path config_file) {
    auto file = std::ifstream(config_file);
    if(!file.is_open()) {
        throw std::runtime_error("no config.txt file at " + config_file.string());
    }
    std::string key;
    std::string value;
    std::unordered_map<std::string, std::string> option_map;
    while(  std::getline(file, key, '=') && std::getline(file, value)) {
        remove_whitespace(key);
        remove_whitespace(value);
        option_map.insert({key, value});
    }

    project_options.redirect_port = option_map.at("REDIRECT_PORT");
    project_options.server_port = option_map.at("SERVER_PORT");
    project_options.domain_names = split(option_map.at("DOMAIN_NAMES"), ",");
    project_options.default_subfolder = option_map.at("DEFAULT_SUBFOLDER");
    project_options.http_strict_transport_security = (option_map.at( "HTTP_STRICT_TRANSPORT_SECURITY") == "true");
    project_options.certificate_file = option_map.at("CERTIFICATE_FILE");
    project_options.key_file = option_map.at("KEY_FILE");

    auto mime_dir = option_map.at("MIME_FOLDER");
    project_options.mime_folder = relative_to(mime_dir, config_file);
    auto webroot = option_map.at("WEBPAGE_FOLDER");
    project_options.webpage_folder = relative_to(webroot, config_file);
    auto tld_file = option_map.at("TLD_FILE");
    project_options.tld_file = relative_to(tld_file, config_file);
    auto key_folder = option_map.at("KEY_FOLDER");
    project_options.key_folder = relative_to(key_folder, config_file);
    auto ip_log_file = option_map.at( "IP_BAN_PATH");
    project_options.ip_ban_file = relative_to(ip_log_file, config_file);

    using namespace std::chrono_literals;
    // static configurables
    project_options.session_timeout = 3600s;
    project_options.handshake_timeout = 180s;
    project_options.keep_alive = 5s;
    project_options.error_timeout = 2s;
}


std::string base64_encode(const std::vector<uint8_t>& data) {
    static constexpr const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string encoded;
    size_t i = 0;
    std::array<uint32_t, 3> octets;
    uint32_t triple;

    while (i < data.size()) {
        octets[0] = i < data.size() ? data[i++] : 0;
        octets[1] = i < data.size() ? data[i++] : 0;
        octets[2] = i < data.size() ? data[i++] : 0;

        triple = (octets[0] << 16) + (octets[1] << 8) + octets[2];

        encoded += base64_chars[(triple >> 18) & 0x3F];
        encoded += base64_chars[(triple >> 12) & 0x3F];
        encoded += (i - 1 < data.size()) ? base64_chars[(triple >> 6) & 0x3F] : '=';
        encoded += (i < data.size()) ? base64_chars[triple & 0x3F] : '=';
    }
    return encoded;
}

std::string build_iso_8601_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto tt  = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&tt);
    return std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}Z",
                       tm.tm_year + 1900,
                       tm.tm_mon + 1,
                       tm.tm_mday,
                       tm.tm_hour,
                       tm.tm_min,
                       tm.tm_sec);
}

std::filesystem::path get_config_path(int argc, const char* argv[]) {
    std::string config_path {};
    for(int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[i+1];
            i++;
        }
    }
    if(config_path.empty()) {
        const char* env = std::getenv("CODEYMCCODEFACE_CONFIG");
        if (env != nullptr) {
            config_path = env;
        }
    }
    if (config_path.empty()) {
        std::filesystem::path exec_path = argv[0];
        auto config_dir = (exec_path / ".."/ "..").lexically_normal();
        auto path = config_dir / "config.txt";
        if(std::filesystem::exists(path)) {
            config_path = config_dir / "config.txt";
        }
    }
    if(config_path.empty()) {
        config_path = "/etc/codeymccodeface/config.txt";
    }
    return config_path;
}

std::string to_hex(uint64_t value) {
    if (value == 0) {
        return "0";
    }
    static constexpr char digits[]  = "0123456789abcdef";
    char buf[16];
    int pos = 16;
    while (value > 0) {
        buf[--pos] = digits[value & 0xF];
        value >>= 4;
    }
    return std::string(&buf[pos], 16 - pos);
}

std::optional<std::string> file_to_string(std::filesystem::path filename) {
    auto sz = std::filesystem::file_size(filename);
    FILE* f = std::fopen(filename.string().c_str(), "rb");
    if (!f) {
        return std::nullopt;
    }
    std::string file(sz, '\0');
    if (std::fread(file.data(), 1, sz, f) != static_cast<size_t>(sz)) {
        std::fclose(f);
        return std::nullopt;
    }
    std::fclose(f);
    return file;
}

}