#pragma once

#define CROW_ENFORCE_WS_SPEC

#if CROW_OPENSSL
#define CROW_ENABLE_SSL
#endif

#include <crow.h>
#include <engine/logging.hxx>
#include <engine/parser/toml.hxx>
#include <cstdint>

namespace crowapp
{
    class CrowApp
    {
      private:
        crow::SimpleApp m_app;
        parser::Toml &m_config;
        logging::Logging &m_log;
        const std::uint16_t m_port;
        const std::uint16_t m_threads;
#if CROW_OPENSSL
        const std::string m_ssl_file_pem;
#endif
        const std::string m_bindaddr;

      public:
        CrowApp(parser::Toml &, logging::Logging &);
        ~CrowApp();

        crow::SimpleApp &crow_get_app();
        const uint16_t crow_get_concurrency();
        parser::Toml &crow_get_config();
        logging::Logging &crow_get_log();
        const std::string &crow_bindaddr();
        const uint16_t &crow_port();
        void crow_run();
        void crow_stop();
    };
}; // namespace crow