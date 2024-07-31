#pragma once

#include "crow.h"

namespace Crow
{
    class CrowApi
    {
    private:
        crow::SimpleApp m_app;
        const std::uint16_t m_port;

    public:
        CrowApi(std::uint16_t);
        ~CrowApi();

        void run();
    };
};