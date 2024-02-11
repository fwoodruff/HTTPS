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
#include "../Runtime/ringbuffer.hpp"

#include <string>
#include <memory>
#include <array>
#include <optional>
#include <variant>

namespace fbw {

using http_reader = std::variant<http_frame, std::exception_ptr, bool>;

class HTTP {
    static constexpr long max_bytes_queued = 1000000;
    static std::optional<ustring> try_extract_header(ustring& m_buffer);

    task<http_reader> try_read_http_request();
    task<void> respond(const std::string& rootdirectory, http_reader http_request);
    task<void> redirect(http_reader header, const std::string& domain);
    task<void> file_to_http(const std::string& rootdirectory, std::string filename);
    void handle_POST(http_frame request);
    ringbuffer<http_reader> m_ringbuffer;
    
    std::string m_folder;
    bool m_redirect;
    std::unique_ptr<stream> m_stream;
    ustring m_buffer;
public:
    task<void> client_receiver();
    task<void> client_responder();
    task<void> exception_handler(std::exception_ptr);
    HTTP(std::unique_ptr<stream> stream, std::string folder, bool redirect);
};

} // namespace fbw
 
#endif // http_hpp
