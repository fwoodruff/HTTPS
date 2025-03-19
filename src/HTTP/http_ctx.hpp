
//
//  http_ctx.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/11/2024.
//

#ifndef http_ctx_hpp
#define http_ctx_hpp

#include "../TCP/stream_base.hpp"
#include <vector>
#include <span>

#include "../Runtime/task.hpp"

namespace fbw {

enum class do_indexing : uint8_t {
    incremental,
    without,
    never
};

struct entry_t {
    std::string name;
    std::string value;
    do_indexing do_index = do_indexing::incremental;
    auto operator<=>(const entry_t&) const = default;
};

}

template<>
struct std::hash<fbw::entry_t> {
    size_t operator()(const fbw::entry_t& s) const noexcept {
        size_t seed = 0;
        fbw::hash_combine(seed, s.name, s.value, s.do_index);
        return seed;
    }
};

namespace fbw {

// todo: for full-duplex, we need an awaitable that signals if either reading or writing possible, consider both HTTP/1.1 and HTTP/2 here
class http_ctx {
public:
    // peak_early_headers()
    // peak_early_data()
    // accept_early()
    // reject_early()
    virtual task<stream_result> read_headers(std::vector<entry_t>& headers) = 0;
    virtual task<std::pair<stream_result, bool>> append_http_data(ustring& buffer) = 0;
    virtual task<stream_result> write_headers(const std::vector<entry_t>& headers, bool end = false) = 0;
    //virtual task<stream_result> write_push_promise(std::vector<entry_t>& headers) = 0;
    virtual task<stream_result> write_data(std::span<const uint8_t> data, bool end = true) = 0;
    virtual ~http_ctx() = default;
};

}

#endif // http_ctx_hpp