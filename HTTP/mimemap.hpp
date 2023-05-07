//
//  mimemap.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2021.
//

#ifndef mimemap_hpp
#define mimemap_hpp

#include <unordered_map>
#include <string>

/*
 Used for handing MIME types
 Multipurpose Internet Mail Extensions indicate the nature and format of a document
 Parsing extensions is non-trivial. There could be multiple dots, '.', not all referring
 to part of the extension
 */

namespace fbw {

[[nodiscard]] std::unordered_map<std::string,std::string> MIME_csv_to_map(std::string filename);
[[nodiscard]] std::unordered_map<std::string,std::string> MIMES(std::string directory_name);
[[nodiscard]] std::string get_MIME(std::string extension);
[[nodiscard]] std::string extension_from_path(std::string path);
std::string Mime_from_file(const std::string &filename);

} // namespace fbw

#endif /* mimemap_hpp */



