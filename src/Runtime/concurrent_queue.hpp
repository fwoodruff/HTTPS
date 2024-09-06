
#ifndef concurrent_queue2_hpp
#define concurrent_queue2_hpp

#include <stdio.h>
#include <mutex>
#include <queue>
#include <vector>
#include <queue>
#include <optional>
#include <semaphore>

#include "hazard_ptr.hpp"
#include <atomic>
#include <optional>
#include <vector>

#include "hazard_ptr.hpp"

static std::atomic<int> globcount = 0;

template<typename T>
class concurrent_queue {
private:
    struct node {
        std::optional<T> data;
        std::atomic<node*> next;
        node() : next(nullptr) {}
        node(T data_) : data(std::move(data_)), next(nullptr) { }
    };

    std::atomic<node*> head;
    std::atomic<node*> tail;

public:
    lock_free_queue() {
        node* dummy = new node();
        head.store(dummy);
        tail.store(dummy);
    }

    ~lock_free_queue() {
        while (node* old_head = head.load()) {
            head.store(old_head->next);
            delete old_head;
        }
    }

    void push(T data) {
        std::atomic<void*>& hp = get_hazard_pointer_for_current_thread();
        node* new_node = new node(std::move(data));
        
        while (true) {
            node* old_tail = tail.load();
            hp.store(old_tail);
            if (old_tail != tail.load()) {
                continue;
            }

            node* next = old_tail->next.load();
            
            if (old_tail == tail.load()) {
                if (next == nullptr) {
                    if (old_tail->next.compare_exchange_weak(next, new_node)) {
                        tail.compare_exchange_strong(old_tail, new_node);
                        hp.store(nullptr);
                        delete_nodes_with_no_hazards();
                        return;
                    }
                } else {
                    tail.compare_exchange_weak(old_tail, next);
                }
            }
        }
    }

    std::optional<T> try_pop() {
        std::atomic<void*>& hp = get_hazard_pointer_for_current_thread();
        while (true) {
            node* old_head = head.load();
            hp.store(old_head);
            
            if (old_head != head.load()) {
                continue;
            }
            
            node* next = old_head->next.load();
            if (next == nullptr) {
                hp.store(nullptr);
                return std::nullopt;  // Queue is empty
            }
            
            if (head.compare_exchange_strong(old_head, next)) {
                T result = std::move(*next->data);
                hp.store(nullptr);
                
                if (outstanding_hazard_pointers_for(old_head)) {
                    reclaim_later(old_head);
                } else {
                    delete old_head;
                }
                delete_nodes_with_no_hazards();
                
                return result;
            }
        }
    }

    void push_bulk(std::vector<T> values) {
        for (auto&& value : values) {
            push(std::move(value));
        }
    }
};

#endif // concurrent_queue_hpp