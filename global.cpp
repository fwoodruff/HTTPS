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

#if __linux__
    const std::string fbw::config_file = "config.txt";
#else
    const std::string fbw::config_file = "/Users/freddiewoodruff/Documents/Programming/HTTPS20/HTTPS20/config.txt";
#endif


void strip(std::string& str) {
    str.erase(std::remove_if(str.begin(), str.end(), isspace), str.end());
}

std::unordered_map<std::string, std::string> get_options(std::string filename) {
    auto file = std::ifstream(filename);
    if(! file.good()) {
        throw std::runtime_error("no config file");
    }
    std::unordered_map<std::string, std::string> options;
    std::pair<std::string, std::string> option;
    while(  std::getline(file, option.first, ':') && std::getline(file, option.second)) {
        strip(option.first);
        strip(option.second);
        options.insert(option);
    }
    return options;
}

std::once_flag onceFlag;

std::string fbw::get_option(std::string option) {
    static std::unordered_map<std::string, std::string> options = get_options(fbw::config_file);
    std::call_once ( onceFlag, [&]{ options = get_options(fbw::config_file); } );
    return options.at(option);
}

