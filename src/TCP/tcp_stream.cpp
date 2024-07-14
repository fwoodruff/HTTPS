//
//  stream.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#include "tcp_stream.hpp"
#include "Awaitables/await_stream.hpp"

#include <unistd.h>
#include <utility>

namespace fbw {

task<stream_result> tcp_stream::read_append(ustring& abuffer, std::optional<milliseconds> timeout) {
    std::array<uint8_t, 1600> readbuff;
    std::span<uint8_t> remaining_buffer = { readbuff.data(), readbuff.size() };
    auto [bytes_read, status] = co_await read(remaining_buffer, timeout);
    if (status == stream_result::ok) {
        abuffer.append(bytes_read.begin(), bytes_read.end());
    }
    co_return status;
}

task<stream_result> tcp_stream::write(ustring abuffer, std::optional<milliseconds> timeout) {
    std::span<const uint8_t> remaining_buffer = {abuffer.data(), abuffer.size()};
    while(remaining_buffer.size() != 0) {
        auto [_, status] = co_await write_some(remaining_buffer, timeout);
        if (status != stream_result::ok) {
            co_return std::move(status);
        }
    }
    co_return stream_result::ok;
}

tcp_stream::tcp_stream(int fd) : stream(), m_fd(fd) { }

readable tcp_stream::read(std::span<uint8_t>& bytes, std::optional<milliseconds> timeout) {
    return readable { m_fd, bytes, timeout };
}

writeable tcp_stream::write_some(std::span<const uint8_t>& bytes, std::optional<milliseconds> timeout) {
    return writeable { m_fd, bytes, timeout };
}

tcp_stream::~tcp_stream() {
    if(m_fd != -1) {
        int err = ::close(m_fd);
        assert(err == 0);
    } // moved from otherwise
}

task<void> tcp_stream::close_notify() {
    if(m_fd != -1) {
        int err = ::close(m_fd);
        assert(err == 0);
        m_fd = -1;
    } // moved from otherwise
    co_return;
}

tcp_stream::tcp_stream(tcp_stream&& other) : m_fd(std::exchange(other.m_fd, -1)) {
}

tcp_stream& tcp_stream::operator=(tcp_stream&& other) {
    this->m_fd = std::exchange(other.m_fd, -1);
    return *this;
}

}
