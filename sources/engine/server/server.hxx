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
        class Server; // Forward declaration Server plugin

        using App = crow::App<middlewares::cors::Cors>;
        class Server
        {
          private:
            std::shared_ptr<App> m_app;

          public:
#ifdef ENGINE_PRO
            friend class engine::server::extend::Server;
#endif
            Server();
            ~Server() = default;
            Server &operator=(const Server &);
            configuration::Configuration *config;
            logging::Logging *log;

            void setup(configuration::Configuration &, logging::Logging &);

            App &get();
            unsigned short concurrency;
            std::string bindaddr;
            std::string name;
            bool ssl_enable;
            unsigned short port;
            std::string certfile;
            std::string keyfile;

            std::future<void> run_async();
            void tick(std::chrono::milliseconds, std::function<void()>);
            void load();
            void stop();
        };
    } // namespace server
} // namespace engine
