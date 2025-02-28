#pragma once

#include <stdint.h>
#include <string>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            namespace type
            {
                enum Bridge {
                    websocket,
                    web
                };
            } // namespace type

            namespace record
            {
                typedef struct Bridge {
                    const std::string path;
                    const type::Bridge type;
                    const uint64_t connections; /* only websocket connections */
                } Bridge;
            } // namespace record
        } // namespace bridge
    } // namespace server
} // namespace engine