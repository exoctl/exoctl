#pragma once

#include "crow.hxx"
#include "conn.hxx"

#define GET_ROUTE(name) Routes::route_##name();

namespace Crow
{
    class Routes
    {
    public:
        Routes(CrowApi &);
        ~Routes();

        void create_routes();
    private:
        CrowApi &m_crow;
        Connection::Context m_context;

        void route_search();
        void route_scan();
    };
}