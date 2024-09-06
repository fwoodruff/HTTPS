

#ifndef hazard_ptr_hpp
#define hazard_ptr_hpp

#include <atomic>
#include <thread>

constexpr unsigned max_hazard_pointers = 100;

std::atomic<void*>& get_hazard_pointer_for_current_thread();

bool outstanding_hazard_pointers_for(void* p);

template<typename T>
void do_delete(void* p) {
    delete static_cast<T*>(p);
}

struct data_to_reclaim {
    void* data;
    std::function<void(void*)> deleter;
    data_to_reclaim* next;
    template<typename T>
    data_to_reclaim(T* p): data(p), deleter(&do_delete<T>), next(0) {}
    ~data_to_reclaim() {
        deleter(data);
    }
};

void add_to_reclaim_list(data_to_reclaim* node);

template<typename T>
void reclaim_later(T* data) {
    add_to_reclaim_list(new data_to_reclaim(data));
}

void delete_nodes_with_no_hazards();

#endif