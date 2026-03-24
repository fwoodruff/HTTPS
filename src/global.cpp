//
//  global.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 13/12/2021.
//

#include "global.hpp"

#include <string>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <unistd.h>
#include <vector>
#include <limits.h>

#include <iomanip>
#include <ctime>

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

    // PROXY_ENDPOINTS=host/path,backend:port/bpath;host2/path2,backend2:port2
    auto proxy_it = option_map.find("PROXY_ENDPOINTS");
    if (proxy_it != option_map.end()) {
        for (const auto& entry : split(proxy_it->second, ";")) {
            auto parts = split(entry, ",");
            if (parts.size() != 2) continue;
            proxy_rule rule;
            // parse frontend: "host/path"
            auto& front = parts[0];
            auto slash = front.find('/');
            if (slash == std::string::npos) {
                rule.frontend_host = front; // no path -> match any path on this host
            } else {
                rule.frontend_host = front.substr(0, slash);
                rule.frontend_path = front.substr(slash); // includes leading '/'
            }
            // parse backend: "host:port[/path]"
            auto& back = parts[1];
            std::string port_and_path;
            if (!back.empty() && back[0] == '[') {
                auto close = back.find(']');
                if (close == std::string::npos || close + 1 >= back.size() || back[close + 1] != ':') {
                    continue;
                }
                rule.backend_host = back.substr(1, close - 1);
                port_and_path = back.substr(close + 2);
            } else {
                auto colon = back.find(':');
                if (colon == std::string::npos) {
                    continue;
                }
                rule.backend_host = back.substr(0, colon);
                port_and_path = back.substr(colon + 1);
            }
            auto path_slash = port_and_path.find('/');
            if (path_slash != std::string::npos) {
                rule.backend_port = static_cast<uint16_t>(std::stoi(port_and_path.substr(0, path_slash)));
                rule.backend_path = port_and_path.substr(path_slash);
            } else {
                rule.backend_port = static_cast<uint16_t>(std::stoi(port_and_path));
            }
            project_options.proxy_endpoints.push_back(std::move(rule));
        }
        // longer frontend_path wins over shorter one (most specific first)
        std::stable_sort(project_options.proxy_endpoints.begin(), project_options.proxy_endpoints.end(),
            [](const proxy_rule& a, const proxy_rule& b) {
                return a.frontend_path.size() > b.frontend_path.size();
            });
    }

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
    auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&tt);
    auto t = std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    std::ostringstream ts;
    ts << t;
    return ts.str();
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

}