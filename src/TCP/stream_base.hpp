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
constexpr milliseconds STANDARD_TIMEOUT = 66s;

class stream_error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

class stream {
public:
    stream() = default;
    // returns true if stream is still open on read
    [[nodiscard]] virtual task<bool> read_append(ustring&, std::optional<milliseconds> timeout = STANDARD_TIMEOUT) = 0;
    [[nodiscard]] virtual task<void> write(ustring, std::optional<milliseconds> timeout = STANDARD_TIMEOUT) = 0;
    [[nodiscard]] virtual task<void> close_notify(std::optional<milliseconds> timeout = STANDARD_TIMEOUT) = 0;
    virtual ~stream() noexcept = default;
    stream(const stream& other) = delete;
    stream(stream&& other) noexcept = delete;
    stream& operator=(const stream& other) = delete;
    stream& operator=(stream&& other) noexcept = delete;
    
};

}

#endif // receiver_hpp
