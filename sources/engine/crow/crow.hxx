#pragma once

#define CROW_ENFORCE_WS_SPEC

#if CROW_OPENSSL
#define CROW_ENABLE_SSL
#endif

#include <crow.h>
#include <engine/log.hxx>
#include <engine/parser/toml.hxx>

namespace Crow
{
    class CrowApp
    {
      private:
        crow::SimpleApp m_app;
        Parser::Toml &m_config;
        Logging::Log &m_log;
        const std::uint16_t m_port;
        const std::uint16_t m_threads;
#if CROW_OPENSSL
        const std::string m_ssl_file_pem;
#endif
        const std::string m_bindaddr;

      public:
        CrowApp(Parser::Toml &, Logging::Log &);
        ~CrowApp();

        crow::SimpleApp &crow_get_app();
        const uint16_t crow_get_concurrency();
        Parser::Toml &crow_get_config();
        Logging::Log &crow_get_log();
        const std::string &crow_bindaddr();
        const uint16_t &crow_port();

        void crow_run();
        void crow_stop();
    };
}; // namespace Crow