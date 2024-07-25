//
//  receiver.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef receiver_hpp
#define receiver_hpp

#include <stdio.h>
#include <memory>

#include "../global.hpp"
#include "../Runtime/task.hpp"
#include <chrono>
#include <optional>



namespace fbw {
using namespace std::chrono_literals;
using namespace std::chrono;

class stream_error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class timeout_error : public stream_error {
    using stream_error::stream_error;
};

enum class stream_result {
    ok,
    write_timeout,
    read_timeout,
    closed,
    awaiting
};

class stream {
public:
    stream() = default;
    // returns true if stream is still open on read
    [[nodiscard]] virtual task<stream_result> read_append(ustring&, std::optional<milliseconds> timeout) = 0;
    [[nodiscard]] virtual task<stream_result> write(ustring, std::optional<milliseconds> timeout) = 0;
    [[nodiscard]] virtual task<stream_result> flush() = 0;

    [[nodiscard]] virtual task<void> close_notify() = 0;
    virtual ~stream() noexcept = default;
    stream(const stream& other) = delete;
    stream(stream&& other) noexcept = default;
    stream& operator=(const stream& other) = delete;
    stream& operator=(stream&& other) noexcept = default;
    
};

}

#endif // receiver_hpp
