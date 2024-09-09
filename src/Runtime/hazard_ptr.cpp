

#include <atomic>
#include <thread>
#include <new>
#include <iostream>
#include <cassert>
#include <array>

#include "hazard_ptr.hpp"

// Abridged from Anthony Williams C++ Concurrency in Action

constexpr size_t program_threads_upper_bound_hint = 32;

// If two threads update neighbouring hazard pointers, the L1 cache will be falsely invalidated.
// However, if one thread updates a hazard pointer, and then sweeps the list of hazard pointers,
// then the neighbouring data will have been prefetched.
// Therefore the preferred alignment depends on runtime access patterns.
// Profiling has not revealed hazard pointer performance bottlenecks.
// hazard_pointer_data has therefore not been overaligned.
struct hazard_pointer_data {
    std::atomic<std::thread::id> id;
    std::atomic<void*> pointer;
};

using enum std::memory_order;

struct hazard_pointer_batch {
    std::array<hazard_pointer_data, program_threads_upper_bound_hint> ptrs{};
    std::atomic<hazard_pointer_batch*> m_next = nullptr;
    // if the program has more threads than this expected upper bound, next() is used to expand the list
    hazard_pointer_batch* next() {
        hazard_pointer_batch* lnext = m_next.load(consume);
        if(lnext != nullptr) {
            return lnext;
        }
        hazard_pointer_batch* new_batch = new hazard_pointer_batch{};
        if(!m_next.compare_exchange_strong(lnext, new_batch, release, consume)) {
            delete new_batch;
            new_batch = lnext;
        }
        assert(new_batch != nullptr);
        return new_batch;
    }
    
    ~hazard_pointer_batch() {
        auto lnext = m_next.load(relaxed);
        if(lnext != nullptr) {
            delete lnext;
        }
    }
};

hazard_pointer::~hazard_pointer() {
    reset_protection();
    delete_nodes_with_no_hazards();
}

hazard_pointer::hazard_pointer(std::atomic<void*>* _ptr) : m_ptr(_ptr) {}

void hazard_pointer::reset_protection() {
    // would still be ok if this was a no-op, so use relaxed
    m_ptr->store(nullptr, relaxed);
}

hazard_pointer_batch hazard_pointers{};


std::atomic<size_t> max_hp_idx = 0;

void update_max(std::atomic<size_t>& atom, size_t value) {
    auto current = atom.load(relaxed); // atom never decreases
    while (current < value && !atom.compare_exchange_weak(current, value, seq_cst, relaxed));
}


class hp_owner {
    hazard_pointer_data* hp;
public:
    hp_owner(hp_owner const&) = delete;
    hp_owner& operator=(hp_owner const&) = delete;
    hp_owner(): hp(nullptr) {
        hazard_pointer_batch* current_batch = &hazard_pointers;
        size_t idx = 0;
        for(unsigned i = 0;; i++) {
            std::thread::id old_id;
            if(current_batch->ptrs[idx].id.compare_exchange_strong(old_id, std::this_thread::get_id(), seq_cst, seq_cst)) {
                hp = &current_batch->ptrs[idx];
                update_max(max_hp_idx, i + 1);
                break;
            }
            if(idx == current_batch->ptrs.size() -1) {
                current_batch = current_batch->next();
                idx = 0;
            } else {
                idx++;
            }
        }
        assert(hp != nullptr);
    }
    std::atomic<void*>& get_pointer() {
        return hp->pointer;
    }
    ~hp_owner() {
        hp->pointer.store(nullptr, seq_cst);
        hp->id.store(std::thread::id(), seq_cst);
        delete_nodes_with_no_hazards();
    }
};

hazard_pointer make_hazard_pointer() {
    thread_local static hp_owner hazard;
    return { &hazard.get_pointer() };
}

bool outstanding_hazard_pointers_for(void* p) {
    hazard_pointer_batch* current_batch = &hazard_pointers;
    size_t idx = 0;
    for(unsigned i = 0; i < max_hp_idx.load(acquire); i++) {
        if(current_batch->ptrs[idx].pointer.load(seq_cst) == p) {
            return true;
        }
        if(idx == current_batch->ptrs.size() - 1) {
            current_batch = current_batch->next();
            idx = 0;
        } else {
            idx++;
        }
    }
    return false;
}


std::atomic<retired_data*> nodes_to_reclaim;

void add_to_garbage(retired_data* node) {
    node->next = nodes_to_reclaim.load(relaxed);
    while(!nodes_to_reclaim.compare_exchange_weak(node->next, node, release, relaxed));
}

void delete_nodes_with_no_hazards() {
    retired_data* current = nodes_to_reclaim.exchange(nullptr, acq_rel);
    while(current) {
        retired_data* const next = current->next;
        if(!outstanding_hazard_pointers_for(current->data)) {
            delete current;
        } else {
            add_to_garbage(current);
        }
        current = next;
    }
}
