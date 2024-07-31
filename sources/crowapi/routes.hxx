#pragma once

#include "crow.hxx"

namespace Crow
{
    class Routes
    {
    public:
        Routes(CrowApi &);
        ~Routes();

        void create_routes();
    private:
        const CrowApi &m_crowapi;
        const std::string m_prefix;

    };
}