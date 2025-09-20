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
#include <queue>

#include <coroutine>
#include <liburing.h>

namespace fbw {

using namespace std::chrono;
enum class IO_direction { Read, Write };

extern struct ::io_uring m_ring;

class reactor {
public:
    reactor();
    void add_task(int fd, std::coroutine_handle<> handle, IO_direction rw,
                  std::optional<milliseconds> timeout = std::nullopt);

    void sleep_for(std::coroutine_handle<> handle, milliseconds duration);
    void sleep_until(std::coroutine_handle<> handle, time_point<steady_clock> when);
    
    size_t task_count();
    void notify();

    std::vector<std::coroutine_handle<>> wait(bool noblock = false);
private:
    std::pair<std::optional<time_point<steady_clock>>, std::vector<std::coroutine_handle<>>>
        wakeup_timeouts( const time_point<steady_clock> &now);

    std::pair<std::optional<time_point<steady_clock>>, std::vector<std::coroutine_handle<>>>
        wakeup_timers(const time_point<steady_clock>& now);

    struct timer_entry {
        time_point<steady_clock> when;
        std::coroutine_handle<> handle;
    };
    struct timer_cmp {
        bool operator()(const timer_entry& a, const timer_entry& b) const noexcept {
            return a.when > b.when;
        }
    };
    
    struct io_handle {
        std::array<std::coroutine_handle<>,2> handle;
        std::array<std::optional<time_point<steady_clock>>,2> wake_up;
        int fd;
    };

    int m_pipe_read;
    int m_pipe_write;
    std::mutex m_mut;
    std::unordered_map<int, io_handle> park_map;
    std::priority_queue<timer_entry, std::vector<timer_entry>, timer_cmp> m_timers;
};

class wait_for {
public:
    wait_for(milliseconds duration);
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> awaiting_coroutine);
    void await_resume();
private:
    milliseconds m_duration;
};

}

#endif // reactor_hpp
