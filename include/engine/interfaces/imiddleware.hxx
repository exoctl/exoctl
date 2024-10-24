#pragma once

#define IS_WEBSOCKET(req) (req.get_header_value("Upgrade") == "websocket")

namespace engine
{
    namespace interface
    {
        struct IMiddleware {
            virtual ~IMiddleware() = default;
        };
    } // namespace interface
} // namespace engine