//
//  HTTP2.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//

#ifndef http2frame_hpp
#define http2frame_hpp

#include <string>
#include "../../global.hpp"

namespace fbw {

constexpr size_t H2_FRAME_HEADER_SIZE = 9;

enum class h2_type : uint8_t {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9,
    ALTSVC = 0xa,
    ORIGIN = 0xc,
    PRIORITY_UPDATE = 0x10,
    unspecified = 0xff,
};

enum h2_flags : uint8_t {
    PRIORITY = 0x20,
    PADDED = 0x08,
    END_HEADERS = 0x04,
    END_STREAM = 0x01,
    ACK = 0x01,
};

enum class h2_settings_code : uint16_t {
    SETTINGS_INVALID = 0x00,
    SETTINGS_HEADER_TABLE_SIZE = 0x01,
    SETTINGS_ENABLE_PUSH = 0x02,
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
    SETTINGS_MAX_FRAME_SIZE = 0x05,
    SETTINGS_MAX_HEADER_LIST_SIZE = 0x06,
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08,
    SETTINGS_NO_RFC7540_PRIORITIES = 0x09,
};

constexpr size_t DEFAULT_MINIMUM_MAX_FRAME_SIZE = 16384;
constexpr size_t MAX_FRAME_SIZE = 16777215;
constexpr size_t MAX_WINDOW_SIZE = 0x7fffffff;
constexpr size_t DEFAULT_INITIAL_MAX_CONCURRENT_STREAMS = 0x7fffffff;
constexpr int32_t DEFAULT_INITIAL_WINDOW_SIZE = 65535;
constexpr size_t DEFAULT_HEADER_LIST_SIZE = 0x7fffffff;
constexpr size_t DEFAULT_HEADER_TABLE_SIZE = 4096;

enum class stream_state {
    idle, // nothing sent
    reserved, // server has sent a push-promise
    open, // server receives a headers frame, and not the last one
    half_closed, // server receives the last headers frame (which may be the first esp. push promise)
    closed, // stream is never used again
};

enum class h2_code {
    NO_ERROR = 0x00,
    PROTOCOL_ERROR = 0x01,
    INTERNAL_ERROR = 0x02,
    FLOW_CONTROL_ERROR = 0x03,
    SETTINGS_TIMEOUT = 0x04,
    STREAM_CLOSED = 0x05,
    FRAME_SIZE_ERROR = 0x06,
    REFUSED_STREAM = 0x07,
    CANCEL = 0x08,
    COMPRESSION_ERROR = 0x09,
    CONNECT_ERROR = 0x0a,
    ENHANCE_YOUR_CALM = 0x0b,
    INADEQUATE_SECURITY = 0x0c,
    HTTP_1_1_REQUIRED = 0x0d,
};

struct setting_values {
    uint32_t header_table_size = DEFAULT_HEADER_TABLE_SIZE;
    uint32_t max_concurrent_streams = DEFAULT_INITIAL_MAX_CONCURRENT_STREAMS;
    uint32_t initial_window_size = DEFAULT_INITIAL_WINDOW_SIZE;
    uint32_t max_frame_size = DEFAULT_MINIMUM_MAX_FRAME_SIZE;
    uint32_t max_header_size = DEFAULT_HEADER_LIST_SIZE;
    bool push_promise_enabled = false;
    bool no_rfc7540_priorities = false;
};

class h2_error : public std::runtime_error {
public:
    h2_code m_error_code;
    h2_error(const std::string& what_arg, h2_code error_code) :
        std::runtime_error(what_arg), m_error_code(error_code) {}
};

struct h2_setting_value {
    h2_settings_code identifier;
    uint32_t value {};
};

struct h2frame {
    h2_type type = h2_type::unspecified;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
    h2frame() = default;
    virtual ustring serialise() const = 0;
    ustring serialise_common(size_t reserve = 0) const;
    virtual std::string pretty() const = 0;
    virtual ~h2frame() = default;
    static std::unique_ptr<h2frame> deserialise(const ustring& frame_data);
};

struct h2_data : public h2frame {
    h2_data();
    uint8_t pad_length {};
    uint32_t stream_dependency {};
    ustring contents;
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_headers : public h2frame {
    h2_headers();
    uint8_t pad_length {};
    bool exclusive {};
    uint32_t stream_dependency {};
    uint8_t weight {};
    ustring field_block_fragment;
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_priority : public h2frame {
    h2_priority();
    bool exclusive {};
    uint32_t stream_dependency {};
    uint8_t weight {};
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_rst_stream : public h2frame {
    h2_rst_stream();
    h2_code error_code = h2_code::NO_ERROR;
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_settings : public h2frame {
    h2_settings();
    std::vector<h2_setting_value> settings;
    ustring serialise() const override;
    std::string pretty() const override;
};

h2_settings construct_settings_frame(setting_values desired_settings, setting_values current_settings);

struct h2_push_promise : public h2frame {
    h2_push_promise();
    uint8_t pad_length {};
    uint32_t promised_stream_id {};
    ustring field_block_fragment;
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_ping : public h2frame {
    h2_ping();
    uint64_t opaque {};
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_goaway : public h2frame {
    h2_goaway();
    uint32_t last_stream_id {};
    h2_code error_code {};
    std::string additional_debug_data;
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_window_update : public h2frame {
    h2_window_update();
    uint32_t window_size_increment {};
    ustring serialise() const override;
    std::string pretty() const override;
};

struct h2_continuation : public h2frame {
    h2_continuation();
    ustring field_block_fragment;
    ustring serialise() const override;
    std::string pretty() const override;
};

} // namespace fbw

#endif // http2frame_hpp