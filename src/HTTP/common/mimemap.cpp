//
//  mimemap.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2021.
//
#include "../../global.hpp"
#include "mimemap.hpp"
#include "string_utils.hpp"

#include <dirent.h>

#include <unordered_map>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <mutex>

namespace fbw {

decltype(MIMES("/")) MIMEmap;
bool init = false;

// responding to an HTTP request, we need to specify the Content-Type of the file we are sending in the HTTP response
// this depends on the extension of the file that was requested.
// we therefore need to map from extension to Content-Type.
std::unordered_map<std::string,std::string> MIME_csv_to_map(const std::filesystem::path& filename) {
    std::ifstream file(filename);
    std::string line;
    std::unordered_map<std::string,std::string> MIME_types;
    while(std::getline(file, line)) {
        std::istringstream s(line);
        std::string field;
        std::vector<std::string> fields;
        while (std::getline(s, field,',')) {
            fields.push_back(field);
        }
        if(fields.size() < 2) {
            throw std::logic_error("failed to read MIMEs");
        }
        MIME_types.insert({fields[0],fields[1]});
    }
    return MIME_types;
}

// I found some files together containing all the possible content types and the associated
// extensions, so this function builds that extension -> content-type map
std::unordered_map<std::string,std::string> MIMES(const std::filesystem::path& directory_name) {
    std::unordered_map<std::string,std::string> map;
    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir(directory_name.c_str())) != nullptr) {
        std::unordered_map<std::string,std::string> mimes;
        while ((ent = ::readdir (dir)) != nullptr) {
            const auto filen = std::filesystem::path(ent->d_name);
            if (filen=="." or filen=="..") {
                continue;
            }
            std::filesystem::path filenn = directory_name / filen;
            auto map = MIME_csv_to_map(filenn);
            mimes.insert(map.cbegin(),map.cend());
        }
        closedir(dir);
        return mimes;
    } else {
        throw std::runtime_error("MIME csv folder not found\n");
    }
}

// The file in the get request header, e.g. /footballscores.html has an extension .html
// This is not always trivial to extract for all MIME types since some extensions have multiple '.' tokens
// and the body of the request could also have one
std::string extension_from_path(const std::filesystem::path& path) {
    std::string filename;
    const std::string slash = "/";
    filename = path.filename();
    const std::string delimiter = ".";
    if(filename.size() < delimiter.size()) return "";
    if(filename.substr(filename.size() - delimiter.size()) == delimiter) {return "";}
    if(filename.find(delimiter) == std::string::npos) {return ""; }
    
    
    for(ssize_t i = filename.size() - delimiter.size(); i >= 0; --i) {
        if(filename.substr(i, delimiter.size()) == delimiter) {
            auto ext = filename.substr(i + delimiter.size());
            if(MIMEmap.contains(ext)) {
                return ext;
            }
        }
    }
    auto str = filename.substr(filename.find_last_of(delimiter) + delimiter.size());
    return str;
}

// Returns the MIME type for a given extension
// e.g. html -> text/html
// This is used in the header of the GET response
std::string get_MIME(std::string extension) {
    try {
        return MIMEmap.at(extension);
    } catch(const std::logic_error& e) {
        throw http_error(415, "Unsupported Media Type");
    } catch(...) {
        assert(false);
    }
}

// that icon at the top of the browser tab has media type image/webp
// otherwise we look up the MIME type
std::string Mime_from_file(const std::filesystem::path &filename) {
    if(filename.filename() == "favicon.ico") {
        return "image/x-icon";
    } else {
        auto ext = extension_from_path(filename);
        if(ext == "jpeg") {
            return "image/jpeg";
        }
        if(ext == "") {
            return "text/plain";
        }
        auto ret = get_MIME(ext);
        return ret;
    }
}

} // namespace fbw
