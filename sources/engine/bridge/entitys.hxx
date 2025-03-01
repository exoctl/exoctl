#pragma once

#include <cstdint>
#include <string>

namespace engine::bridge
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
        using Bridge = struct Bridge {
            const std::string path;
            const type::Bridge type;
            const uint64_t connections; /* only websocket connections */
        };
    } // namespace record
} // namespace engine::bridge
