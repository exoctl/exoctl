#pragma once

#include "crow.hxx"
#include "conn.hxx"
#include <mutex>

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
        std::mutex m_mtx;

        void route_search();
        void route_scan();
    };
}