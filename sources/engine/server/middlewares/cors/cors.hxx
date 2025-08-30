#pragma once

#include <crow/middlewares/cors.h>
#include <engine/configuration/configuration.hxx>

namespace engine::server::middlewares::cors
{
    class Cors : public crow::CORSHandler
    {
      public:
        Cors() = default;
        ~Cors() = default;

        void setup(configuration::Configuration &);
        void load();

        template <typename Context>
        void before_handle(crow::request &req,
                           crow::response &res,
                           Context &ctx)
        {
            crow::CORSHandler::before_handle(req, res, ctx);
        }

        template <typename Context>
        void after_handle(crow::request &req, crow::response &res, Context &ctx)
        {
            crow::CORSHandler::after_handle(req, res, ctx);
        }

      private:
        configuration::Configuration *config_;
    };
} // namespace engine::server::middlewares::cors