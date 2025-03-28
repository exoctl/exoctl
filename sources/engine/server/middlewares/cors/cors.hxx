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

        inline void setup(configuration::Configuration &);
        inline void load();

        // Adicione os métodos necessários para o middleware
        template <typename Context>
        void before_handle(crow::request &req,
                           crow::response &res,
                           Context &ctx)
        {
            crow::CORSHandler::before_handle(
                req, res, ctx);
        }

        template <typename Context>
        void after_handle(crow::request &req, crow::response &res, Context &ctx)
        {
            crow::CORSHandler::after_handle(
                req, res, ctx);
        }

      private:
        configuration::Configuration *m_config;
    };
} // namespace engine::server::middlewares::cors