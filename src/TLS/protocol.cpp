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

#include <iostream>
#include <iomanip>
#include <memory>
#include <utility>
#include <thread>

#include <queue>

#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif

namespace fbw {

using enum ContentType;

TLS::TLS(std::unique_ptr<stream> output_stream) : m_client(std::move(output_stream) ) {}

task<stream_result> TLS::read_append_common(ustring& data, std::optional<milliseconds> timeout, bool return_early) {
    guard g { &m_async_read_mut };
    co_await m_async_read_mut.lock();
    auto initial_size = data.size();
    if(!early_data_buffer.empty()) {
        data.append(std::move(early_data_buffer));
        early_data_buffer.clear();
    }
    for(;;) {
        if(data.size() > initial_size and (return_early or m_engine.m_expected_read_record >= HandshakeStage::application_data)) {
            co_return stream_result::ok;
        }
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return stream_result::closed;
        }
        ustring input_data;
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
        ustring input_data;
        auto read_res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(read_res != stream_result::ok) {
            co_return read_res;
        }
        m_engine.process_net_read(output, early_data_buffer, input_data, project_options.handshake_timeout);
        auto bio_res = co_await net_write_all();
        if(bio_res != stream_result::ok) {
            co_return bio_res;
        }
    }
}

task<stream_result> TLS::read_append(ustring& data, std::optional<milliseconds> timeout) {
    return read_append_common(data, timeout, false);
}

task<stream_result> TLS::read_append_early_data(ustring& data, std::optional<milliseconds> timeout) {
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
task<stream_result> TLS::write(ustring data, std::optional<milliseconds> timeout) {
    m_engine.process_net_write(output, data, timeout);
    m_engine.process_net_flush(output); // remove this
    return net_write_all();
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

// application data is sent on a buffered stream so the pattern of record sizes reveals much less
task<stream_result> TLS::flush() {
    m_engine.process_net_flush(output);
    return net_write_all();
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
        ustring input_data;
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

}// namespace fbw
