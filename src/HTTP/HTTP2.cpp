//
//  HTTP2.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//

#include "../Runtime/task.hpp"

#include "HTTP.hpp"
#include "HTTP2.hpp"


namespace fbw {

std::vector<h2frame> extract_frames(ustring& buffer)  {
    return {};
}

task<bool> HTTP2::handle_frame(h2frame frame) {
    co_return true;
}

[[nodiscard]] task<void> HTTP2::client() {
    std::vector<h2frame> priority_queue;
    ustring buffer;
    using namespace std::chrono_literals;
    while(true) {
        if(priority_queue.size() < 100) {
            bool should_block = priority_queue.empty();
            auto res = co_await m_stream->read_append(buffer, should_block? project_options.keep_alive : 0ms);
            if(res != stream_result::ok) {
                co_return;
            }
            auto frames = extract_frames(buffer);
            for(auto frame : frames) {
                priority_queue.push_back(frame);
            }
        }
        auto frame = priority_queue.back();
        priority_queue.pop_back();
        bool go_away = co_await handle_frame(frame);
        if (go_away) {
            co_return;
        }
    }
}
HTTP2::HTTP2(std::unique_ptr<stream> stream, std::string folder) : m_stream(std::move(stream)), m_folder(folder) {}

} // namespace 

