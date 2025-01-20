#pragma once

#define CROW_ENFORCE_WS_SPEC
#define CROW_MAIN

#if CROW_OPENSSL
#define CROW_ENABLE_SSL
#endif

#include <crow.h>
#include <cstdint>
#include <engine/configuration/configuration.hxx>
#include <engine/logging.hxx>
#include <engine/parser/toml.hxx>

namespace engine
{
    namespace server
    {
        using App = crow::App<>;
        class Server
        {
          private:
            App m_app;
            configuration::Configuration &m_config;
            logging::Logging &m_log;

          public:
            Server(configuration::Configuration &, logging::Logging &);
            ~Server() = default;

            App &get();
            configuration::Configuration &get_config();
            logging::Logging &get_log();
            unsigned short concurrency;
            std::string bindaddr;
            unsigned short port;
            const std::string &ssl_certificate_path;
            void run();
            void stop();
        };
    } // namespace server
} // namespace engine