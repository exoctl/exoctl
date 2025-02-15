#pragma once

#define CROW_ENFORCE_WS_SPEC
#define CROW_MAIN

#if CROW_OPENSSL
#define CROW_ENABLE_SSL
#endif

#include <crow.h>
#include <cstdint>
#include <engine/configuration/configuration.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/logging/logging.hxx>
#include <engine/parser/toml.hxx>
#include <engine/plugins/plugins.hxx>
#include <memory>

namespace engine
{
    namespace server
    {
        using App = crow::App<>;
        class Server
#ifdef ENGINE_PRO
            : public interface::IPlugins
#endif
        {
          private:
            std::shared_ptr<App> m_app;
            configuration::Configuration *m_config;
            logging::Logging *m_log;

          public:
            Server();
            ~Server() = default;
            Server &operator=(const Server &);

            void setup(configuration::Configuration &, logging::Logging &);

            App &get();
            configuration::Configuration &get_config();
            logging::Logging &get_log();
            unsigned short concurrency;
            std::string bindaddr;
            std::string name;
            unsigned short port;
            std::string ssl_certificate_path;
#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
            void run();
            void stop();
        };
    } // namespace server
} // namespace engine
