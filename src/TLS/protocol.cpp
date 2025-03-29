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
    guard g { &m_async_read_mut };
    m_async_read_mut.lock();
    if(!early_data_buffer.empty() and m_engine.m_expected_read_record >= HandshakeStage::application_data) {
        data.append(std::move(early_data_buffer));
        early_data_buffer.clear();
        co_return stream_result::ok;
    }
    auto initial_size = data.size();
    for(;;) {
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return stream_result::closed;
        }
        ustring input_data;
        auto read_res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(read_res != stream_result::ok) {
            co_return read_res;
        }
        m_engine.read_append_impl_sync(output, data, input_data, timeout);
        auto bio_res = co_await bio_write_all(output);
        if(bio_res != stream_result::ok) {
            co_return bio_res;
        }
        if(data.size() > initial_size and m_engine.m_expected_read_record == HandshakeStage::application_data) {
            co_return stream_result::ok;
        }
    }
}

task<stream_result> TLS::read_append_early_data(ustring& data, std::optional<milliseconds> timeout) {
    guard g { &m_async_read_mut };
    m_async_read_mut.lock();
    if(!early_data_buffer.empty() and m_engine.m_expected_read_record >= HandshakeStage::client_early_data) {
        data.append(std::move(early_data_buffer));
        early_data_buffer.clear();
        co_return stream_result::ok;
    }
    auto initial_size = data.size();
    for(;;) {
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return stream_result::closed;
        }
        ustring input_data;
        auto read_res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(read_res != stream_result::ok) {
            co_return read_res;
        }
        m_engine.read_append_impl_sync(output, data, input_data, timeout);
        auto bio_res = co_await bio_write_all(output);
        if(bio_res != stream_result::ok) {
            co_return bio_res;
        }
        if(data.size() > initial_size) {
            co_return stream_result::ok;
        }
    }
}

task<std::string> TLS::perform_hello() {
    guard g { &m_async_read_mut };
    m_async_read_mut.lock();
    for(;;) {
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return "";
        }
        if(m_engine.m_expected_read_record > HandshakeStage::client_hello) {
            co_return m_engine.alpn();
        }
        ustring input_data;
        auto read_res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(read_res != stream_result::ok) {
            co_return "";
        }
        m_engine.read_append_impl_sync(output, early_data_buffer, input_data, project_options.handshake_timeout);
        auto bio_res = co_await bio_write_all(output);
        if(bio_res != stream_result::ok) {
            co_return "";
        }
    }
}

task<stream_result> TLS::await_handshake_finished() {
    guard g { &m_async_read_mut };
    m_async_read_mut.lock();
    for(;;) {
        if(m_engine.m_expected_read_record == HandshakeStage::application_closed) {
            co_return stream_result::closed;
        }
        if(m_engine.m_expected_read_record > HandshakeStage::client_handshake_finished) {
            co_return stream_result::ok;
        }
        ustring input_data;
        auto read_res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(read_res != stream_result::ok) {
            co_return read_res;
        }
        m_engine.read_append_impl_sync(output, early_data_buffer, input_data, project_options.handshake_timeout);
        auto bio_res = co_await bio_write_all(output);
        if(bio_res != stream_result::ok) {
            co_return bio_res;
        }
    }
}

// application code calls this to send data to the client
task<stream_result> TLS::write(ustring data, std::optional<milliseconds> timeout) {
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
    m_engine.flush_sync(output);
    co_return co_await bio_write_all(output);
}

// applications call this when graceful not abrupt closing of a connection is desired
task<void> TLS::close_notify() {
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
