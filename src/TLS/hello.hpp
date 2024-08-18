#ifndef hello_hpp
#define hello_hpp

#include <array>
#include "../global.hpp"
#include "TLS_enums.hpp"

namespace fbw {

struct extension {
    ExtensionType type;
    ustring data;
};

struct key_share {
    NamedGroup key_type;
    ustring key;
};

struct hello_record_data {
    uint16_t legacy_client_version = 0;
    std::array<uint8_t, 32> m_client_random {};
    ustring client_session_id {};
    std::vector<cipher_suites> cipher_su{};
    std::vector<uint8_t> compression_types{};

    std::vector<std::string> server_names{};
    std::vector<std::string> application_layer_protocols{};
    std::vector<SignatureScheme> supported_groups{};
    std::vector<uint8_t> ec_point_formats{};
    ustring session_ticket{};
    bool encrypt_then_mac = true;
    bool extended_master_secret = true;
    bool client_heartbeat = false;
    bool server_heartbeat = false;

    std::vector<SignatureAlgorithm> signature_algorithms{};
    std::vector<uint16_t> supported_versions{};
    std::vector<PskKeyExchangeMode> PSK_key_exchange_modes{};
    std::vector<key_share> shared_keys{};

    bool truncated_hmac = false;

};

hello_record_data parse_client_hello(const ustring& hello_contents);

}



#endif // hello_hpp