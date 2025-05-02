//
//  concurrent_queue.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 7/7/2024.
//

#ifndef concurrent_queue_hpp
#define concurrent_queue_hpp

#include "hazard_ptr.hpp"

#include <stdio.h>
#include <mutex>
#include <queue>
#include <vector>
#include <queue>
#include <optional>
#include <atomic>

template<typename T>
class concurrent_queue {
private:
    static T* sentinel;

    struct node : public hazard_pointer_obj_base<node> {
        std::atomic<T*> data {sentinel};
        std::atomic<node*> next;
        node() : next(nullptr) {}
        node(T data_) : data(std::move(data_)), next(nullptr) { }
    };

    std::atomic<node*> head;
    std::atomic<node*> tail;

public:
    concurrent_queue() {
        node* dummy = new node();
        head.store(dummy, std::memory_order::relaxed);
        tail.store(dummy, std::memory_order::relaxed);
    }

    ~concurrent_queue() {
        while (node* old_head = head.load(std::memory_order::relaxed)) {
            head.store(old_head->next, std::memory_order::relaxed);
            delete old_head;
        }
    }

    void push(T data) {
        hazard_pointer hp = make_hazard_pointer();
        node* new_next = new node;
        T* data_ptr = new T(std::move(data));
        assert(data_ptr != sentinel);
        for(;;) {
            node* old_tail = hp.protect(tail);
            T* old_data = sentinel;
            if(old_tail->data.compare_exchange_strong(old_data, data_ptr)) {
                node* old_next = nullptr;
                if(!old_tail->next.compare_exchange_strong(old_next, new_next)) {
                    delete new_next;
                    new_next = old_next;
                }
                node* const current_tail_ptr = old_tail;
                while(!tail.compare_exchange_weak(old_tail, new_next) && old_tail == current_tail_ptr);
                return;
            } else {
                node* old_next = nullptr;
                if(old_tail->next.compare_exchange_strong(old_next, new_next)) {
                    old_next = new_next;
                    new_next = new node; 
                }
                node* const current_tail_ptr = old_tail;
                while(!tail.compare_exchange_weak(old_tail, old_next) && old_tail == current_tail_ptr);
            }
        }
    }

    std::optional<T> try_pop() {
        hazard_pointer hp = make_hazard_pointer();
        for(;;) {
            node* old_head = hp.protect(head);
            if(old_head == tail.load()) {
                return std::nullopt;
            }
            node* next = old_head->next.load();
            if (next == nullptr) {
                return std::nullopt;
            }
            if (head.compare_exchange_strong(old_head, next)) {
                std::unique_ptr<T> result_ptr { old_head->data.exchange(nullptr) };
                old_head->retire();
                T result = std::move(*result_ptr.get());
                return { std::move(result) };
            }
        }
    }

    void push_bulk(std::vector<T> values) {
        for (auto&& value : values) {
            push(std::move(value));
        }
    }
};

extern char sentinel_byte;
template<typename T>
T* concurrent_queue<T>::sentinel = reinterpret_cast<T*>(&sentinel_byte);

#endif // concurrent_queue_hpp