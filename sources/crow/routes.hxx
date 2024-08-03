#pragma once

#include "crow.hxx"
#include "conn.hxx"

#include <mutex>

#define GET_ROUTE(name) Routes::route_##name();

#define SOCKET_OPEN_CONNECTION_CONTEXT \
    std::lock_guard<std::mutex> _(m_mtx); \
    m_context.conn_add(&conn);            \
    m_context.conn_send_msg(&conn, "{\"connection\": \"sucessfull\"}");

#define SOCKET_CLOSE_CONNECTION_CONTEXT  \
    std::lock_guard<std::mutex> _(m_mtx); \
    m_context.conn_erase(&conn, reason);

namespace Crow
{
    class Routes
    {
    public:
        Routes(CrowApi &);
        ~Routes();

        void routes_create();
    private:
        CrowApi &m_crow;
        Connection::Context m_context;
        std::mutex m_mtx;

        void route_search();
        void route_scan();
    };
}