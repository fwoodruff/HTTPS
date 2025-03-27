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

task<stream_result> TLS::read_append(ustring& data, std::optional<milliseconds> timeout) {
    co_return co_await read_append_impl(data, timeout, false, false);
}

task<stream_result> TLS::read_append_early_data(ustring& data, std::optional<milliseconds> timeout) {
    co_return co_await read_append_impl(data, timeout, true, false);
}

task<stream_result> TLS::await_handshake_finished() {
    ustring dummy;
    co_return co_await read_append_impl(dummy, project_options.handshake_timeout, false, true);
    assert(dummy.empty());
}

// application code calls this to decrypt and read data
task<stream_result> TLS::read_append_impl(ustring& app_data, std::optional<milliseconds> app_timeout, bool return_early_data, bool return_client_finished) {
    size_t initial_size = app_data.size();
    guard g { &m_async_read_mut };
    m_async_read_mut.lock();
    if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
        co_return stream_result::closed;
    }
    for(;;) {
        if(return_client_finished and m_engine.m_expected_read_record == HandshakeStage::application_data) {
            co_return stream_result::ok;
        }
        ustring input_data;
        std::queue<packet_timed> output;
        auto read_res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(read_res != stream_result::ok) {
            co_return read_res;
        }
        auto engine_res = m_engine.read_append_impl_sync(output, app_data, input_data, app_timeout, return_early_data, return_client_finished);
        auto bio_res = co_await bio_write_all(output);
        if(bio_res != stream_result::ok) {
            co_return bio_res;
        }
        if(engine_res != stream_result::ok) {
            co_return stream_result::closed;
        }
        if(initial_size != app_data.size()) {
            co_return stream_result::ok;
        }
    }
}

task<std::string> TLS::perform_hello() {
    for(;;) {
        ustring data;
        std::queue<packet_timed> output;
        auto res = co_await m_client->read_append(data, project_options.handshake_timeout);
        if(res != stream_result::ok) {
            co_return "";
        }
        auto opt_alpn = m_engine.perform_hello_sync(output, data);
        
        auto res1 = co_await bio_write_all(output);
        if(res1 != stream_result::ok) {
            co_return "";
        }
        if(opt_alpn) {
            co_return *opt_alpn;
        }
    }
}

// application code calls this to send data to the client
task<stream_result> TLS::write(ustring data, std::optional<milliseconds> timeout) {
    std::queue<packet_timed> output;
    m_engine.write_sync(output, data, timeout);
    co_return co_await bio_write_all(output);
}

task<stream_result> TLS::bio_write_all(std::queue<packet_timed>& packets) {
    for(;;) {
        packet_timed packet;
        co_await m_async_write_mut.lock();
        guard g { &m_async_write_mut };
        {
            std::scoped_lock lk { m_engine.m_write_queue_mut };
            if(packets.empty()) {
                co_return stream_result::ok;
            }
            packet = std::move(packets.front());
            packets.pop();
        }
        stream_result res = co_await m_client->write(packet.data, packet.timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    while(!packets.empty()) {
        auto packet = std::move(packets.front());
        packets.pop();
        stream_result res = co_await m_client->write(packet.data, packet.timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    co_return stream_result::ok;
}

// application data is sent on a buffered stream so the pattern of record sizes reveals much less
task<stream_result> TLS::flush() {
    std::queue<packet_timed> output;
    m_engine.flush_sync(output);
    co_return co_await bio_write_all(output);
}

// applications call this when graceful not abrupt closing of a connection is desired
task<void> TLS::close_notify() {
    std::queue<packet_timed> output;
    m_engine.close_notify_sync_write(output);
    auto res = co_await bio_write_all(output);
    if(res != stream_result::ok) {
        co_return;
    }
    guard g { &m_async_read_mut };
    m_async_read_mut.lock();
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
        auto res2 = m_engine.close_notify_sync_finish(input_data);
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
