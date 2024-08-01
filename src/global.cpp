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

// Function to convert comma-separated string to vector of strings
std::vector<std::string> split_string(const std::string& input, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(input);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        remove_whitespace(token);
        tokens.push_back(token);
    }
    return tokens;
}

const options& option_singleton() {
    const std::filesystem::path config_file = "config.txt";
    static options project_options;
    static std::once_flag flag;
    std::call_once(flag, [&] {
        auto file = std::ifstream(config_file);
        if(! file.good()) {
            throw std::runtime_error("no config file at " + config_file.string());
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
        project_options.domain_names = split_string(option_map.at("DOMAIN_NAMES"), ',');
        project_options.key_folder = option_map.at("KEY_FOLDER");
        project_options.certificate_file = option_map.at("CERTIFICATE_FILE");
        project_options.key_file = option_map.at("KEY_FILE");
        project_options.webpage_folder = option_map.at("WEBPAGE_FOLDER");
        project_options.default_subfolder = option_map.at("DEFAULT_SUBFOLDER");
        project_options.tld_file = option_map.at("TLD_FILE");
        project_options.mime_folder = option_map.at("MIME_FOLDER");
        project_options.http_strict_transport_security = (option_map.at( "HTTP_STRICT_TRANSPORT_SECURITY") == "true");
    });

    using namespace std::chrono_literals;
    // static configurables
    project_options.session_timeout = 3600s;
    project_options.handshake_timeout = 180s;
    project_options.keep_alive = 5s;
    project_options.error_timeout = 2s;

    return project_options;
}


std::unordered_map<std::string, std::string> get_options(std::filesystem::path filename) {
    auto file = std::ifstream(filename);
    if(! file.good()) {
        throw std::runtime_error("no config file at " + filename.string());
    }
    std::unordered_map<std::string, std::string> options;
    std::pair<std::string, std::string> option;
    while(  std::getline(file, option.first, '=') && std::getline(file, option.second)) {
        remove_whitespace(option.first);
        remove_whitespace(option.second);
        options.insert(option);
    }
    return options;
}



}