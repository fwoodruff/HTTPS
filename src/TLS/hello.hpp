//
//  hello.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 18/08/2024.
//

#ifndef hello_hpp
#define hello_hpp

#include <array>
#include "../global.hpp"
#include "TLS_utils.hpp"
#include "TLS_enums.hpp"
#include <unordered_set>
#include <ranges>

namespace fbw {

struct extension_t {
    ExtensionType type;
    std::span<const uint8_t> data;
};

struct key_share {
    named_group key_type;
    std::vector<uint8_t> key;
};

struct pre_shared_key_entry {
    std::vector<uint8_t> m_key;
    uint32_t m_obfuscated_age;
};

struct preshared_key_ext {
    std::ptrdiff_t idxbinders_ext = 0;
    std::ptrdiff_t idxbinders = 0;
    std::vector<pre_shared_key_entry> m_keys;
    std::vector<std::vector<uint8_t>> m_psk_binder_entries;
};

template <typename T, size_t ChunkBytes>
struct chunked_view {
    std::span<const uint8_t> bytes;

    constexpr chunked_view() = default;
    constexpr explicit chunked_view(std::span<const uint8_t> b) : bytes(b) {}

    struct iterator {
        using iterator_category = std::forward_iterator_tag;
        using value_type        = T;
        using difference_type   = ptrdiff_t;

        const uint8_t* p = nullptr;

        constexpr T operator*() const noexcept {
            uint64_t acc = 0;
            for (size_t i = 0; i < ChunkBytes; ++i) {
                acc = (acc << 8) | p[i];
            }
            return static_cast<T>(acc);
        }

        constexpr iterator& operator++() noexcept { p += ChunkBytes; return *this; }
        constexpr iterator operator++(int) noexcept { auto tmp = *this; ++(*this); return tmp; }

        constexpr bool operator==(const iterator& o) const noexcept { return p == o.p; }
        constexpr bool operator!=(const iterator& o) const noexcept { return p != o.p; }
    };

    constexpr iterator begin() const noexcept { return iterator{bytes.data()}; }
    constexpr iterator end() const noexcept {
        auto even_len = (bytes.size() / ChunkBytes) * ChunkBytes;
        return iterator{bytes.data() + even_len};
    }

    constexpr size_t size() const noexcept { return bytes.size() / ChunkBytes; }
    constexpr bool empty() const noexcept { return bytes.empty(); }
};

struct server_name {
    uint8_t type;
    std::string_view name;
};

std::string_view to_string_view(std::span<const uint8_t> bytes) noexcept;


std::optional<server_name> decode_server_name(std::span<const uint8_t>& rest);

template <size_t HeaderSize>
std::optional<std::string_view> decode_string_view(std::span<const std::uint8_t>& rest) {
    if(rest.empty()) {
        return std::nullopt;
    }
    auto res = der_span_read(rest, 0, HeaderSize);
    rest = rest.subspan(res.size() + HeaderSize);
    return { to_string_view(res) };
}


template <typename T, std::optional<T> (*DecodeFn)(std::span<const std::uint8_t>&)>
class decode_view {
    std::span<const uint8_t> bytes;
public:
    decode_view(std::span<const std::uint8_t> b)
        : bytes(b) {}
    decode_view() = default;

    struct iterator {
        using iterator_category = std::forward_iterator_tag;
        using value_type        = T;
        using difference_type   = ptrdiff_t;

        std::span<const std::uint8_t> rest;

        std::optional<T> current{};

        iterator& operator++() {
            current = (*DecodeFn)(rest);
            return *this;
        }
        const T& operator*() const noexcept { 
            assert(current.has_value());
            return *current;
        }
        bool operator==(iterator end) const noexcept { 
            return !current.has_value();
        }
    };

    iterator begin() const {
        iterator it{bytes};
        ++it;
        return it;
    }
    
    iterator end() const noexcept { return {}; }
    bool empty() const noexcept { return bytes.empty(); }
};

template <size_t HeaderSize>
using string_view_view = decode_view<std::string_view, &decode_string_view<HeaderSize>>;

using server_name_view = decode_view<server_name, &decode_server_name>;

using signature_schemes_view = chunked_view<signature_scheme, 2>;
using cipher_suites_view = chunked_view<cipher_suites, 2>;
using named_group_view = chunked_view<named_group, 2>;
using supported_versions_view = chunked_view<uint16_t, 2>;
using certificate_compression_algorithm_view = chunked_view<certificate_compression_algorithm, 2>;

struct hello_record_data {
    std::unordered_set<ExtensionType> parsed_extensions;

    uint16_t legacy_client_version = 0;
    std::array<uint8_t, 32> m_client_random {};
    std::vector<uint8_t> client_session_id;
    cipher_suites_view cipher_su;
    std::span<const uint8_t> compression_types;

    server_name_view server_names;
    string_view_view<1> application_layer_protocols;
    named_group_view supported_groups;
    signature_schemes_view signature_schemes;
    std::optional<preshared_key_ext> pre_shared_key;
    certificate_compression_algorithm_view certificate_compression;
    std::optional<uint16_t> record_size_limit = std::nullopt;
    uint16_t padding_size = 0;
    bool encrypt_then_mac = true;
    bool extended_master_secret = true;
    bool client_heartbeat = false;
    bool server_heartbeat = false;

    std::vector<PskKeyExchangeMode> pskmodes;

    std::vector<SignatureAlgorithm> signature_algorithms;
    supported_versions_view supported_versions;
    std::vector<PskKeyExchangeMode> PSK_key_exchange_modes;
    std::vector<key_share> shared_keys;

    bool truncated_hmac = false;
};

hello_record_data parse_client_hello(const std::vector<uint8_t>& hello_contents);

// server hello extensions
void write_alpn_extension(tls_record& record, const std::string& alpn);
void write_renegotiation_info(tls_record& record);
void write_heartbeat(tls_record& record);
void write_key_share(tls_record& record, const key_share& pubkey_ephem);
void write_key_share_request(tls_record& record, named_group chosen_group);
void write_supported_versions(tls_record& record, uint16_t version);
void write_cookie(tls_record& record);
void write_pre_shared_key_extension(tls_record& record, uint16_t key_id);
void write_early_data_encrypted_ext(tls_record& record);

std::vector<uint8_t> get_shared_secret(std::array<uint8_t, 32> server_private_key_ephem, key_share peer_key);
std::pair<std::vector<uint8_t>, key_share> process_client_key_share(const key_share& client_keyshare);
std::vector<uint8_t> make_hello_random(uint16_t version, bool requires_hello_retry);

}



#endif // hello_hpp