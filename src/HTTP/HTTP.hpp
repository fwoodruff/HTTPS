//
//  HTTP.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#ifndef http_hpp
#define http_hpp

#include "../TCP/tcp_stream.hpp"
#include "string_utils.hpp"
#include "../global.hpp"
#include "../Runtime/task.hpp"

#include <string>
#include <memory>

namespace fbw {

class HTTP {
    static constexpr long max_bytes_queued = 1000000;
    static std::optional<ustring> try_extract_header(ustring& m_buffer);

    

    task<std::optional<http_frame>> try_read_http_request();
    task<void> respond(const std::string& rootdirectory, http_frame http_request);
    task<void> redirect(http_frame header, std::string domain);
    task<void> file_to_http(const std::string& rootdirectory, std::string filename);
    void handle_POST(http_frame request);
    
    std::string m_folder;
    bool m_redirect;
    std::unique_ptr<stream> m_stream;
    ustring m_buffer;
public:
    task<void> client();
    HTTP(std::unique_ptr<stream> stream, std::string folder, bool redirect);
};

} // namespace fbw
 
#endif // http_hpp
