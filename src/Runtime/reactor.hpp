//
//  reactor.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 23/04/2023.
//

#ifndef reactor_hpp
#define reactor_hpp

#include <stdio.h>
#include <vector>

#include <chrono>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <array>


#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif

using namespace std::chrono;
enum class IO_direction { Read, Write };


class reactor {
public:
    reactor();
    void add_task(int fd, std::coroutine_handle<> handle, IO_direction rw,
                  std::optional<milliseconds> timeout = std::nullopt);
    
    size_t task_count();
    void notify();

    std::vector<std::coroutine_handle<>> wait(bool noblock = false);
private:
    std::pair<std::optional<time_point<steady_clock>>, std::vector<std::coroutine_handle<>>>
        wakeup_timeouts( const time_point<steady_clock> &now);
    
    struct io_handle {
        std::array<std::coroutine_handle<>,2> handle;
        std::array<std::optional<time_point<steady_clock>>,2> wake_up;
        int fd;
    };

    int m_pipe_read;
    int m_pipe_write;
    std::mutex m_mut;
    std::unordered_map<int, io_handle> park_map;
};

#endif // reactor_hpp
