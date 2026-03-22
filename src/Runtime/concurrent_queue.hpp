//
//  concurrent_queue.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 7/7/2024.
//

#ifndef concurrent_queue_hpp
#define concurrent_queue_hpp

#include "hazard_ptr.hpp"

#include <atomic>
#include <optional>
#include <utility>

// Standard Michael-Scott lock-free FIFO queue.
// head is a dummy sentinel node; tail is the last enqueued node (or == head if empty).
// Supports lock-free O(1) bulk splice of a pre-built node chain.
template<typename T>
class concurrent_queue {
public:
    struct node : public hazard_pointer_obj_base<node> {
        T data {};
        std::atomic<node*> next {nullptr};
        node() = default;
        explicit node(T d) : data(std::move(d)) {}
    };

    // Pre-built singly-linked chain for a single atomic bulk insert.
    // Build with push(); hand to concurrent_queue::splice() or blocking_queue::splice().
    struct chain {
        node* head  = nullptr;
        node* tail  = nullptr;
        size_t count = 0;

        void push(T data) {
            auto* n = new node(std::move(data));
            if (!tail) { head = tail = n; }
            else { tail->next.store(n, std::memory_order_relaxed); tail = n; }
            ++count;
        }

        chain() = default;
        chain(const chain&) = delete;
        chain& operator=(const chain&) = delete;

        chain(chain&& o) noexcept
            : head(std::exchange(o.head, nullptr))
            , tail(std::exchange(o.tail, nullptr))
            , count(std::exchange(o.count, 0)) {}

        chain& operator=(chain&& o) noexcept {
            if (this != &o) {
                this->~chain();
                head  = std::exchange(o.head,  nullptr);
                tail  = std::exchange(o.tail,  nullptr);
                count = std::exchange(o.count, 0);
            }
            return *this;
        }

        // Append other to the end of this chain, leaving other empty.
        void append(chain&& other) {
            if (!other.head) return;
            if (!tail) { *this = std::move(other); return; }
            tail->next.store(other.head, std::memory_order_relaxed);
            tail   = other.tail;
            count += other.count;
            other.head = other.tail = nullptr;
        }

        ~chain() {
            while (head) {
                auto* n = head;
                head = n->next.load(std::memory_order_relaxed);
                delete n;
            }
        }
    };

    concurrent_queue() {
        node* dummy = new node();
        head.store(dummy, std::memory_order_relaxed);
        tail.store(dummy, std::memory_order_relaxed);
    }

    ~concurrent_queue() {
        node* h = head.load(std::memory_order_relaxed);
        while (h) {
            node* next = h->next.load(std::memory_order_relaxed);
            delete h;
            h = next;
        }
    }

    void push(T data) {
        chain c;
        c.push(std::move(data));
        splice(std::move(c));
    }

    // Atomically appends all nodes in c to the back of the queue in O(1).
    void splice(chain c) {
        if (!c.head) return;
        c.tail->next.store(nullptr, std::memory_order_relaxed);
        hazard_pointer hp = make_hazard_pointer();
        for (;;) {
            node* t    = hp.protect(tail);
            node* next = t->next.load(std::memory_order_acquire);
            if (t != tail.load(std::memory_order_acquire)) continue;
            if (next == nullptr) {
                if (t->next.compare_exchange_weak(next, c.head,
                                                  std::memory_order_release,
                                                  std::memory_order_relaxed)) {
                    // Best-effort swing; other threads will help if we're preempted.
                    tail.compare_exchange_weak(t, c.tail,
                                               std::memory_order_release,
                                               std::memory_order_relaxed);
                    c.head = nullptr;
                    c.tail = nullptr;  // ownership transferred; disable dtor free
                    return;
                }
            } else {
                // Another thread is mid-push; help advance tail.
                tail.compare_exchange_weak(t, next,
                                           std::memory_order_release,
                                           std::memory_order_relaxed);
            }
        }
    }

    std::optional<T> try_pop() {
        hazard_pointer hp = make_hazard_pointer();
        for (;;) {
            node* h     = hp.protect(head);
            node* t     = tail.load(std::memory_order_acquire);
            node* first = h->next.load(std::memory_order_acquire);
            if (h != head.load(std::memory_order_acquire)) continue;
            if (h == t) {
                if (first == nullptr) return std::nullopt;
                // Tail is lagging; help it forward.
                tail.compare_exchange_weak(t, first,
                                           std::memory_order_release,
                                           std::memory_order_relaxed);
                continue;
            }
            // Read value before the CAS. Safe for std::coroutine_handle<> (copy == move).
            T val = first->data;
            if (head.compare_exchange_strong(h, first,
                                             std::memory_order_release,
                                             std::memory_order_relaxed)) {
                h->retire();  // old dummy is no longer reachable
                return val;
            }
        }
    }

private:
    std::atomic<node*> head;
    std::atomic<node*> tail;
};

#endif // concurrent_queue_hpp
