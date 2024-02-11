#include "Runtime/task.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "global.hpp"
#include <vector>



namespace fbw {
task<void> quicmain();


/*

data:
we need a map from address -> [coroutine + messages received]
we also need a priority queue for request timeouts, to spuriously wake those coroutines - could reuse reactor's here

when a udp socket is polled, coroutine waiting on postman_awaitable resumes and calls recvfrom returning a message with a from address.
we look up the address in the map, if new, we create an async task, otherwise we resume the address's coroutine handle

an awaitable is responsible for sending a message and setting an optional timeout for wakeup
on wakeup, we have the address so we can look up the messages in the map for the address

We wrap the sender-timeout awaitable, with an exponential backoff and eventual give up. send and receive a single linked operation.

Once the handshake is complete, we can spawn a new task for each stream. A stream will need its own awaitable. WIP

*/



struct mail_item {
    ustring message;
    struct sockaddr_storage rsvp_addr;
};

class postman_awaitable { // listener
public:
    postman_awaitable(int server_fd);
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept;
    mail_item await_resume();
};

class connection_awaitable { // what the task waits on
    connection_awaitable(ustring message, uint64_t timeout_ms); // sends the message, and awakes on the timeout
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept;
    void await_resume(); // inbound messages are looked up by address
};


} // namespace fbw