//
//  quic_utils.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 28/11/2025.
//

#ifndef quic_visitor_hpp
#define quic_visitor_hpp

#include "types.hpp"
#include "../Runtime/task.hpp"

namespace fbw::quic {
    
task<void> visit_packet(const var_packet& packet);

}

#endif