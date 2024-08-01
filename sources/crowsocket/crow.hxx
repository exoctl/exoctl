#pragma once

#include <crow.h>

namespace Crow
{
    class CrowApi
    {
    private:
        const std::uint16_t m_port;
        crow::SimpleApp m_app;

    public:
        CrowApi(std::uint16_t);
        ~CrowApi();

        crow::SimpleApp &get_app();
        void run();
    };
};