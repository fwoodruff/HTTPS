//
//  HTTP.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#ifndef http_hpp
#define http_hpp

#include "../../TCP/tcp_stream.hpp"
#include "string_utils.hpp"
#include "../../global.hpp"
#include "../../Runtime/task.hpp"

#include <string>
#include <memory>

namespace fbw {

class HTTP {
    static std::optional<http_header> try_extract_header(ustring& m_buffer);

    [[nodiscard]] task<std::optional<http_frame>> try_read_http_request();
    [[nodiscard]] task<stream_result> respond(const std::filesystem::path& rootdirectory, http_frame http_request);
    [[nodiscard]] task<void> redirect(http_frame header);
    [[nodiscard]] task<stream_result> send_file(const std::filesystem::path& rootdirectory, const std::string& subfolder, std::filesystem::path filename, bool send_body);
    [[nodiscard]] task<stream_result> send_range(const std::filesystem::path& rootdirectory, const std::string& subfolder, std::filesystem::path filename, std::pair<ssize_t, ssize_t> range, bool send_body);
    [[nodiscard]] task<stream_result> send_multi_ranges(const std::filesystem::path& rootdirectory, const std::string& subfolder, std::filesystem::path filename, std::vector<std::pair<ssize_t, ssize_t>> ranges, bool send_body);
   
    [[nodiscard]] task<stream_result> send_body_slice(const std::filesystem::path& file_path, ssize_t begin, ssize_t end);

    void write_body(ustring request);
    [[nodiscard]] task<void> send_error(http_error e);
    
    std::string m_folder;
    bool m_redirect;
    std::unique_ptr<stream> m_stream;
    ustring m_buffer;
    bool handled_request = false;
public:
    [[nodiscard]] task<void> client();
    HTTP(std::unique_ptr<stream> stream, std::string folder, bool redirect);
};

ssize_t get_file_size(std::filesystem::path filename);

} // namespace fbw
 
#endif // http_hpp
