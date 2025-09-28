//
//  HTTP.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "HTTP.hpp"

#include <string>

namespace fbw {

std::string moved_301() {
    return
R"(<html>
    <head>
        <title>301 Moved Permanently</title>
    </head>
    <body>
        <h1>301 Moved Permanently</h1>
        <p>Redirecting</p>
    </body>
</html>
)";
}

};// namespace fbw
