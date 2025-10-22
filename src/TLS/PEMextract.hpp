//
//  PEMextract.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 04/12/2021.
//

#ifndef PEMextract_hpp
#define PEMextract_hpp

#include "../global.hpp"

#include <stdio.h>
#include <array>
#include <string>
#include <vector>

namespace fbw {

std::array<unsigned char,32> privkey_from_file(const std::filesystem::path& filename);

std::vector<std::vector<uint8_t>> der_cert_from_file(const std::filesystem::path& filename);

std::array<uint8_t,32> privkey_for_domain(const std::string& domain);

std::vector<std::vector<uint8_t>> der_cert_for_domain(const std::string& domain);
} //namespace fbw


#endif // PEMextract_hpp
