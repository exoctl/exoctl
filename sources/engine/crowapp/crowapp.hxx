#pragma once

#define CROW_ENFORCE_WS_SPEC
#define CROW_MAIN

#if CROW_OPENSSL
#define CROW_ENABLE_SSL
#endif

#include <crow.h>
#include <cstdint>
#include <engine/configuration/configuration.hxx>
#include <engine/crowapp/bridge/gateway/websocket/middlewares/jwtauth.hxx>
#include <engine/logging.hxx>
#include <engine/parser/toml.hxx>

namespace engine
{
    namespace crowapp
    {
        using App = crow::App<middleware::websocket::JWTAuth>;
        class CrowApp
        {
          private:
            App m_app;
            configuration::Configuration &m_config;
            logging::Logging &m_log;

          public:
            CrowApp(configuration::Configuration &, logging::Logging &);
            ~CrowApp();

            App &get_app();
            const uint16_t get_concurrency();
            configuration::Configuration &get_config();
            logging::Logging &get_log();
            const std::string &get_bindaddr();
            const uint16_t &get_port();
            void run();
            void stop();
        };
    } // namespace crowapp
} // namespace engine