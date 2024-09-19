#pragma once

namespace Crow
{
    namespace Types
    {
        enum Route {
            websocket,
            web
        };
    } // namespace Types

    namespace Structs
    {
        typedef struct Endpoints {
            const std::string path;
            const Types::Route type;
            const uint64_t connections; /* only websocket connections */
        } Endpoints;
    } // namespace Structs
} // namespace Crow