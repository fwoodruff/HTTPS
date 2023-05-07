//
//  acceptable.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#ifndef acceptable_hpp
#define acceptable_hpp

#include <cstdio>
#include <span>
#include <optional>


#ifdef __cpp_impl_coroutine
    #include <coroutine>
#else
    #include <experimental/coroutine>
#endif

namespace std {
    namespace experimental {}
    using namespace experimental;
}

namespace fbw {

class tcp_stream;

class acceptable {
public:
    acceptable(int sfd);
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept;
    std::optional<tcp_stream> await_resume();
private:
    int m_server_fd;
};
}

#endif /* acceptable_hpp */
