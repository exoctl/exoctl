#pragma once

#define CROW_ENFORCE_WS_SPEC
#define CROW_MAIN

#include <crow.h>
#include <cstdint>
#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/logging/logging.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/extend/server.hxx>
#include <engine/server/middlewares/cors/cors.hxx>
#include <memory>

namespace engine
{
    namespace server
    {
        class Server : public crow::App<middlewares::cors::Cors>
        {
          public:
            friend class engine::server::extend::Server;

            Server() =default;
            ~Server() = default;
            Server &operator=(const Server &);
            configuration::Configuration *config;
            logging::Logging *log;

            void setup(configuration::Configuration &, logging::Logging &);

            unsigned short concurrency;
            std::string baddr;
            std::string name;
            bool ssl_enable;
            unsigned short port;
            std::string certfile;
            std::string keyfile;

            std::future<void> start();
            void load();
            void end();
        };
    } // namespace server
} // namespace engine
