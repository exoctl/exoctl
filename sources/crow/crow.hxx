#pragma once

#define CROW_ENFORCE_WS_SPEC

#include <crow.h>

namespace Crow
{
    class CrowApi
    {
    private:
        const std::uint16_t m_port;
        const std::string m_bindaddr;
        crow::SimpleApp m_app;

    public:
        CrowApi(const std::string, std::uint16_t);
        ~CrowApi();

        void crow_set_ssl_file(const std::string &, const std::string & = "");
        crow::SimpleApp &crow_get_app();
        void crow_run();
    };
};