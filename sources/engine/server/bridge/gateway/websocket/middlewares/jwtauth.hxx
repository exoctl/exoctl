#pragma once

#include <crow/middleware.h>
#include <engine/interfaces/imiddleware.hxx>
#include <iostream>

namespace engine::server::middleware::websocket
{
    struct JWTAuth : public crow::ILocalMiddleware {
        struct context {
        };

        void before_handle(crow::request &req,
                           crow::response &res,
                           context &ctx)
        {
            exit(1);
        }

        void after_handle(crow::request &, crow::response &, context &)
        {
            // websocket not called this func
        }
    };
} // namespace engine::server::middleware::websocket