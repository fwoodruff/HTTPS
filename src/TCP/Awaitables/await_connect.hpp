//
//  await_connect.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 14/03/2026.
//

#ifndef await_connect_hpp
#define await_connect_hpp

#include <optional>
#include <string>
#include <coroutine>
#include <cstdint>

namespace fbw {

class tcp_stream;

// co_await connectable{"192.168.1.1", 8080} → optional<tcp_stream>
class connectable {
public:
    connectable(std::string host, uint16_t port) noexcept;
    ~connectable();
    connectable(connectable&&) noexcept;
    connectable(const connectable&) = delete;
    connectable& operator=(const connectable&) = delete;

    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> cont);
    std::optional<tcp_stream> await_resume();
private:
    std::string m_host;
    uint16_t m_port;
    int m_fd = -1;
};

} // namespace fbw

#endif // await_connect_hpp
