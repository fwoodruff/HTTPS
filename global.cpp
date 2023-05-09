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

std::string fbw::absolute_directory(std::string directory) {
    if(directory.empty()) {
        std::cerr << "failed to get current working directory" << std::endl;
        std::terminate();
    }
    if(directory[0] == '/') {
        return directory; // directory is absolute
    }
    std::vector<char> absolute_working;
    absolute_working.resize(PATH_MAX);
    void* res = getcwd(absolute_working.data(), PATH_MAX);
    if (res == nullptr) {
        std::cerr << "failed to get current working directory" << std::endl;
        std::terminate();
    }
    std::string base_dir(absolute_working.data());
    
    return base_dir + "/" + directory;
}

std::once_flag onceFlag;

std::string fbw::get_option(std::string option) {
    static std::unordered_map<std::string, std::string> options = get_options(fbw::config_file);
    std::call_once ( onceFlag, [&]{ options = get_options(fbw::config_file); } );
    return options.at(option);
}

