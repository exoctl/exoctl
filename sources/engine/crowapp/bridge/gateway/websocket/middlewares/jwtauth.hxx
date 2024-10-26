#pragma once

#include <crow.h>
#include <engine/interfaces/imiddleware.hxx>
#include <iostream>

namespace engine::crowapp::middleware::websocket
{
    struct JWTAuth : public interface::IMiddleware,
                     public crow::ILocalMiddleware {
        struct context {
        };

        void before_handle(crow::request &p_req,
                           crow::response &res,
                           context &ctx)
        {
           
        }

        void after_handle(crow::request &, crow::response &, context &)
        {
            // websocket not called this func
        }
    };
} // namespace engine::crowapp::middleware::websocket