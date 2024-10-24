#pragma once

#include <engine/crowapp/crowapp.hxx>
#include <engine/interfaces/imiddleware.hxx>

namespace engine::crowapp::middleware
{
    namespace websocket
    {
        struct Auth : public interface::IMiddleware {
            struct context {
            };

            void before_handle(crow::request &req,
                               crow::response &res,
                               context &ctx)
            {
                if (IS_WEBSOCKET(req)) {
                    
                }
            }

            void after_handle(crow::request &, crow::response &, context &)
            {
                // websocket not called this func
            }
        };
    } // namespace websocket

    namespace web
    {
        struct Auth : public interface::IMiddleware {
            struct context {
            };

            void before_handle(crow::request &req,
                               crow::response &res,
                               context &ctx)
            {
                if (!IS_WEBSOCKET(req)) {
                }
            }

            void after_handle(crow::request &, crow::response &, context &)
            {
            }
        };
    } // namespace web
} // namespace engine::crowapp::middleware