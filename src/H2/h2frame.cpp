
#include "h2frame.hpp"

namespace fbw {

using enum h2_code;

ustring h2frame::serialise() const {
    return {};
}

std::unique_ptr<h2frame> h2frame::deserialise(ustring) {
    return {};
}

}