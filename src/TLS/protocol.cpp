//
//  TLS.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "protocol.hpp"

#include "PEMextract.hpp"
#include "../global.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/tcp_stream.hpp"
#include "../Runtime/executor.hpp"

#include <iomanip>
#include <memory>
#include <utility>
#include <thread>
#include <deque>

#include <queue>

#include <coroutine>


namespace fbw {

using enum ContentType;

std::string TLS::get_ip() {
    return m_client->get_ip();
}

TLS::TLS(std::unique_ptr<stream> output_stream) : m_client(std::move(output_stream) ) {}

task<stream_result> TLS::read_append_common(std::deque<uint8_t>& data, std::optional<milliseconds> timeout, bool return_early) {
    guard g { &m_async_read_mut };
    co_await m_async_read_mut.lock();
    auto initial_size = data.size();
    if(!early_data_buffer.empty()) {
        data.insert(data.end(), early_data_buffer.begin(), early_data_buffer.end());
        early_data_buffer.clear();
    }
    for(;;) {
        if(data.size() > initial_size and (return_early or m_engine.m_expected_read_record >= HandshakeStage::application_data)) {
            co_return stream_result::ok;
        }
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return stream_result::closed;
        }
        std::deque<uint8_t> input_data;
        auto read_timeout = std::optional(project_options.handshake_timeout);
        if(m_engine.m_expected_read_record == HandshakeStage::application_data) {
            read_timeout = timeout;
        }
        if(m_engine.m_expected_read_record > HandshakeStage::client_early_data and return_early) {
            read_timeout = timeout;
        }
        auto read_res = co_await m_client->read_append(input_data, read_timeout);
        if(read_res != stream_result::ok) {
            co_return read_res;
        }
        m_engine.process_net_read(output, data, input_data, timeout);
        auto bio_res = co_await net_write_all();
        if(bio_res != stream_result::ok) {
            co_return bio_res;
        }
    }
}

task<stream_result> TLS::bail_if_http(const std::deque<uint8_t>& input_data) {
    std::string redirect_response = 
        "HTTP/1.1 302 Found\r\nLocation: https://" +
        project_options.default_subfolder.string() +
        "/assets/never.mp4\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";
    if(m_engine.m_expected_read_record == HandshakeStage::client_hello) {
        if(!input_data.empty() and (input_data.front() < 19 or input_data.front() > 27)) {
            std::vector<uint8_t> data{redirect_response.begin(), redirect_response.end() };
            co_await m_client->write(data, project_options.error_timeout);
            co_return stream_result::closed;
        }
    }
    co_return stream_result::ok;
}

task<stream_result> TLS::await_message(HandshakeStage stage) {
    guard g { &m_async_read_mut };
    co_await m_async_read_mut.lock();
    for(;;) {
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return stream_result::closed;
        }
        if(m_engine.m_expected_read_record > stage) {
            co_return stream_result::ok;
        }
        std::deque<uint8_t> input_data;
        auto read_res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(read_res != stream_result::ok) {
            co_return read_res;
        }
        if(co_await bail_if_http(input_data) != stream_result::ok) {
            co_return read_res;
        }
        m_engine.process_net_read(output, early_data_buffer, input_data, project_options.handshake_timeout);
        auto bio_res = co_await net_write_all();
        if(bio_res != stream_result::ok) {
            co_return bio_res;
        }
    }
}

task<stream_result> TLS::read_append(std::deque<uint8_t>& data, std::optional<milliseconds> timeout) {
    return read_append_common(data, timeout, false);
}

task<stream_result> TLS::read_append_early_data(std::deque<uint8_t>& data, std::optional<milliseconds> timeout) {
    return read_append_common(data, timeout, true);
}

task<stream_result> TLS::await_hello() {
    return await_message(HandshakeStage::client_hello);
}

task<stream_result> TLS::await_handshake_finished() {
    return await_message(HandshakeStage::client_handshake_finished);
}

std::string TLS::alpn() {
    return m_engine.alpn();
}

// application code calls this to send data to the client
task<stream_result> TLS::write(std::vector<uint8_t> data, std::optional<milliseconds> timeout) {
    m_engine.process_net_write(output, data, timeout);
    co_return co_await net_write_all();
}

task<stream_result> TLS::net_write_all() {
    bool already_acquired = m_write_region.exchange(true);
    if(already_acquired) {
        co_return stream_result::ok;
    }
    for(;;) {
        packet_timed packet;
        {
            std::scoped_lock lk { m_engine.m_write_queue_mut };
            if(output.empty()) {
                m_write_region.store(false);
                co_return stream_result::ok;
            }
            packet = std::move(output.front());
            output.pop();
        }
        stream_result res = co_await m_client->write(packet.data, packet.timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    co_return stream_result::ok;
}

// applications call this when graceful not abrupt closing of a connection is desired
task<void> TLS::close_notify() {
    m_engine.process_close_notify(output);
    auto res = co_await net_write_all();
    if(res != stream_result::ok) {
        co_return;
    }
    guard g { &m_async_read_mut };
    co_await m_async_read_mut.lock();
    do {
        std::deque<uint8_t> input_data;
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return;
        }
        auto res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(res != stream_result::ok) {
            co_return;
        }
        std::queue<packet_timed> output_end;
        auto res2 = m_engine.close_notify_finish(input_data);
        if(res2 == stream_result::awaiting) {
            continue;
        }
        if(res2 != stream_result::ok) {
            co_return;
        }
        co_await m_client->close_notify();
        co_return;
    } while(false);
}

task<stream_result> read_append_maybe_early(stream* p_stream, std::deque<uint8_t>& buffer, std::optional<std::chrono::milliseconds> timeout) {
    auto tls_stream = dynamic_cast<TLS*>(p_stream);
    if(tls_stream) {
        return tls_stream->read_append_early_data(buffer, timeout);
    } else {
        return p_stream->read_append(buffer, timeout);
    }
}

buffer::buffer(size_t size): buffer_size(size){}

std::deque<std::vector<uint8_t>> buffer::write(const std::span<const uint8_t> data, bool do_flush) {
    std::deque<std::vector<uint8_t>> out;
    size_t offset = 0;
    const size_t total = data.size();
    while (offset < total) {
        if (m_buffer.empty()) {
            m_buffer.reserve(buffer_size);
        }
        const size_t take = std::min(buffer_size - m_buffer.size(), total - offset);
        m_buffer.insert(m_buffer.end(), data.begin() + offset, data.begin() + offset + take);
        offset += take;
        if (m_buffer.size() == buffer_size) {
            out.push_back(std::exchange(m_buffer, {}));
        }
    }
    if (do_flush and !m_buffer.empty()) {
        out.push_back(std::exchange(m_buffer, {}));
    }
    return out;
}

store_buffer::store_buffer(size_t size) : buffer_size(size) {}

void store_buffer::push_back(const std::span<const uint8_t> data) {
    
    size_t offset = 0;
    const size_t total = data.size();
    while (offset < total) {
        if (current.empty()) {
            current.reserve(buffer_size);
        }
        const size_t take = std::min(buffer_size - current.size(), total - offset);
        current.insert(current.end(), data.begin() + offset, data.begin() + offset + take);
        offset += take;
        if (current.size() == buffer_size) {
            m_buffer.push_back(std::exchange(current, {}));
        }
    }
}

std::deque<std::vector<uint8_t>> store_buffer::get(bool do_flush) {
    auto out = std::exchange(m_buffer, {});
    if(do_flush) {
        out.push_back(std::exchange(current, {}));
    }
    return out;
}

ssize_t store_buffer::remaining() {
    return buffer_size - current.size();
}
    
} // namespace fbw
