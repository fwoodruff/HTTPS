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

task<stream_result> TLS::read_append_early(ustring& data, std::optional<milliseconds> timeout) {
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
    for(;;) {
        if(return_client_finished and m_engine.m_expected_record == HandshakeStage::application_data) {
            co_return stream_result::ok;
        }
        ustring input_data;
        std::vector<packet_timed> output;
        auto res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
        auto [result, handshake_done] = m_engine.read_append_impl_sync(output, app_data, input_data, app_timeout, return_early_data, return_client_finished);
        if(result != stream_result::ok) {
            co_return result;
        }
        auto res2 = co_await bio_write_all(output);
        if(res2 != stream_result::ok) {
            co_return res2;
        }
        if(handshake_done and return_client_finished) {
            co_return stream_result::ok;
        }
        if(initial_size != app_data.size()) {
            co_return stream_result::ok;
        }
    }
}

task<std::string> TLS::perform_hello() {
    for(;;) {
        ustring data;
        std::vector<packet_timed> output;
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
    std::vector<packet_timed> output;
    m_engine.write_sync(output, data, timeout); // todo : bring these back
    co_return co_await bio_write_all(output);
}

task<stream_result> TLS::bio_write_all(const std::vector<packet_timed>& packets) const{
    for(auto& packet : packets) {
        stream_result res = co_await m_client->write(packet.data, packet.timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    co_return stream_result::ok;
}

// application data is sent on a buffered stream so the pattern of record sizes reveals much less
task<stream_result> TLS::flush() {
    std::vector<packet_timed> output;
    m_engine.flush_sync(output);
    co_return co_await bio_write_all(output);
}

// applications call this when graceful not abrupt closing of a connection is desired
task<void> TLS::close_notify() {
    std::vector<packet_timed> output;
    m_engine.close_notify_sync_write(output);
    auto res = co_await bio_write_all(output);
    if(res != stream_result::ok) {
        co_return;
    }
    do {
        ustring input_data;
        auto res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(res != stream_result::ok) {
            co_return;
        }
        std::vector<packet_timed> output_end;
        auto res2 = m_engine.close_notify_sync_finish(output_end, input_data);
        if(res2 == stream_result::awaiting) {
            continue;
        }
        if(res2 != stream_result::ok) {
            co_return;
        }
        co_await bio_write_all(output);
        co_await m_client->close_notify();
        co_return;
    } while(false);
}

task<void> make_write_task(task<stream_result> write_task, std::shared_ptr<TLS> this_ptr) {
    std::optional<ssl_error> error_ssl;
    std::vector<fbw::packet_timed> output;
    co_await this_ptr->m_async_mut.lock();
    guard {&this_ptr->m_async_mut};
    try {
        if(this_ptr->m_engine.connection_done) {
            co_return;
        }
        co_await write_task;
        co_return;
    } catch(const ssl_error& e) {
        error_ssl = e;
        goto END; // cannot co_await inside a catch block
    } catch(const std::exception& e) {
        goto END2;
    }
    END:
    this_ptr->m_engine.server_alert_sync(output, error_ssl->m_l, error_ssl->m_d);
    this_ptr->m_engine.connection_done = true;
    co_await this_ptr->bio_write_all(output);
    co_return;
    END2:
    this_ptr->m_engine.server_alert_sync(output, AlertLevel::fatal, AlertDescription::decode_error);
    this_ptr->m_engine.connection_done = true;
    co_await this_ptr->bio_write_all(output);
    co_return;
}

void TLS::schedule(task<stream_result> write_task) {
    sync_spawn(make_write_task(std::move(write_task), shared_from_this()));
}

}// namespace fbw
