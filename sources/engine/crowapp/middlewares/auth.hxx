#pragma once

#include <engine/crowapp/crowapp.hxx>
#include <iostream>

namespace engine::crowapp::middleware
{
    namespace websocket
    {
        struct Auth {
            struct context {
            };

            void before_handle(crow::request &req,
                               crow::response &res,
                               context &ctx)
            {
                
            }

            void after_handle(crow::request &, crow::response &, context &)
            {
            }
        };
    } // namespace websocket

    namespace web
    {

    }
} // namespace engine::crowapp::middleware