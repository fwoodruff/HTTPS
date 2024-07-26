//
//  HTTP2.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//


#ifndef http2_hpp
#define http2_hpp

#include "../TCP/tcp_stream.hpp"
#include "string_utils.hpp"
#include "../global.hpp"
#include "../Runtime/task.hpp"

#include <memory>
#include <string>

namespace fbw {


struct h2frame {

};

class HTTP2 {

public:
    [[nodiscard]] task<void> client();
    HTTP2(std::unique_ptr<stream> stream, std::string folder);
private:
    [[nodiscard]] task<bool> handle_frame(h2frame frame);
    std::unique_ptr<stream> m_stream;
    std::string m_folder;
};

} // namespace fbw
#endif // http2_hpp