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

    [[nodiscard]] task<std::optional<http_frame>> try_read_http_request();
    [[nodiscard]]  task<stream_result> respond(const std::filesystem::path& rootdirectory, http_frame http_request);
    [[nodiscard]] task<void> redirect(http_frame header, std::string domain);
    [[nodiscard]] task<stream_result> send_file(const std::filesystem::path& rootdirectory, std::filesystem::path filename, std::optional<std::pair<ssize_t, ssize_t>> range = std::nullopt);
   
    void write_body(ustring request);
    [[nodiscard]] task<void> send_error(http_error e);
    
    std::string m_folder;
    bool m_redirect;
    std::unique_ptr<stream> m_stream;
    ustring m_buffer;
public:
    [[nodiscard]] task<void> client();
    HTTP(std::unique_ptr<stream> stream, std::string folder, bool redirect);
};

} // namespace fbw
 
#endif // http_hpp
