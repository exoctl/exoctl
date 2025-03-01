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
#include <engine/plugins/plugins.hxx>
#include <memory>

namespace engine
{
    namespace server
    {
        using App = crow::App<>;
        class Server : public interface::IBind
#ifdef ENGINE_PRO
            ,
                       public interface::IPlugins
#endif
        {
          private:
            std::shared_ptr<App> m_app;

          public:
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
            unsigned short port;
            std::string ssl_certificate_path;
            void bind_to_lua(sol::state_view &) override;
#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
            std::future<void> run_async();

            void tick(std::chrono::milliseconds d, std::function<void()> f);
            void stop();
        };
    } // namespace server
} // namespace engine
