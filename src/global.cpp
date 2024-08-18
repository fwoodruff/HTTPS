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
#include <sstream>
#include <filesystem>

namespace fbw {

void remove_whitespace(std::string& str) {
    str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
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

void init_options() {
    const std::filesystem::path config_file = "config.txt"; // todo: make this a command line argument
    
    auto file = std::ifstream(config_file);
    if(! file.good()) {
        throw std::runtime_error("no config.txt file at " + (std::filesystem::current_path()/config_file.relative_path()).string());
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
    project_options.key_folder = option_map.at("KEY_FOLDER");
    project_options.certificate_file = option_map.at("CERTIFICATE_FILE");
    project_options.key_file = option_map.at("KEY_FILE");
    project_options.webpage_folder = option_map.at("WEBPAGE_FOLDER");
    project_options.default_subfolder = option_map.at("DEFAULT_SUBFOLDER");
    project_options.tld_file = option_map.at("TLD_FILE");
    project_options.mime_folder = option_map.at("MIME_FOLDER");
    project_options.http_strict_transport_security = (option_map.at( "HTTP_STRICT_TRANSPORT_SECURITY") == "true");


    using namespace std::chrono_literals;
    // static configurables
    project_options.session_timeout = 3600s;
    project_options.handshake_timeout = 180s;
    project_options.keep_alive = 5s;
    project_options.error_timeout = 2s;

}




}