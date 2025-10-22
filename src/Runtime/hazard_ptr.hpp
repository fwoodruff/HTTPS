
#ifndef hazard_ptr_hpp
#define hazard_ptr_hpp

// follows interface for https://en.cppreference.com/w/cpp/header/hazard_pointer
// replace when C++26 available

#include <atomic>
#include <thread>

void delete_nodes_with_no_hazards();
bool outstanding_hazard_pointers_for(void* ptr);
struct retired_data {
    void* data;
    void (*deleter)(void*);
    retired_data* next{};
    
    template<typename T>
    retired_data(T* pointer): data(pointer), deleter([](void* ptr) { delete static_cast<T*>(ptr); }) {}
    ~retired_data() {
        deleter(data);
    }
};
void add_to_garbage(retired_data* node);
template<typename T>
void reclaim_later(T* data) {
    add_to_garbage(new retired_data(data));
}

template<typename T>
struct hazard_pointer_obj_base;

struct hazard_pointer {
    
    template<typename T>
    T* protect(const std::atomic<T*>& src) noexcept {
        using enum std::memory_order;
        for(;;) {
            T* local = src.load(acquire);
            m_ptr->store(local, seq_cst);
            if (local == src.load(acquire)) {
                return local;
            }
        }
    }
    void reset_protection();
    ~hazard_pointer();
    hazard_pointer(std::atomic<void*>*);
private:
    std::atomic<void*>* m_ptr;
};
hazard_pointer make_hazard_pointer();

template<typename T>
struct hazard_pointer_obj_base {
public:
    void retire() noexcept {
        hazard_pointer hazard_ptr = make_hazard_pointer();
        hazard_ptr.reset_protection();
        if (outstanding_hazard_pointers_for(this)) {
            reclaim_later(this);
        } else {
            delete static_cast<T*>(this);
        }
        delete_nodes_with_no_hazards();
    }
};

#endif