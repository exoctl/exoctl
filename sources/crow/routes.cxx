#include "routes.hxx"
#include "endpoints.hxx"
#include "iscan.hxx"
#include "scan.hxx"
#include "conn.hxx"

namespace Crow
{
    Routes::Routes(CrowApi &p_crow) : m_crow(p_crow)
    {
    }

    Routes::~Routes()
    {
    }

    void Routes::routes_create()
    {
        GET_ROUTE(search);
        GET_ROUTE(scan);
    }

    void Routes::route_search()
    {
        CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), ROUTE_SEARCH)
            .onerror([&](crow::websocket::connection& conn, const std::string& error_message)
                {
                    
                })
            .onaccept([&](const crow::request &req, void **userdata)
                { 
                    /* TODO: Create validatior for sucessful connection */
                    return true; 
                })
            .onopen([&](crow::websocket::connection &conn)
                {
                    std::lock_guard<std::mutex> _(m_mtx);
                    m_context.conn_add(&conn);
                    m_context.conn_send_msg(&conn, "Connection with your ip '" + conn.get_remote_ip() + "' Opened...");
                })
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t with_status_code)
                { 
                    std::lock_guard<std::mutex> _(m_mtx);
                    m_context.conn_erase(&conn, reason);
                })
            .onmessage([&](crow::websocket::connection &conn, const std::string &data, bool is_binary)
                {
                    std::lock_guard<std::mutex> _(m_mtx);
                    if (is_binary)
                    {
                    }else
                    {
                    } 
                });
    }

    void Routes::route_scan()
    {
        Analysis::Scan *Scan = new Analysis::Scan();

        SCAN(Scan, yara, "test");

        CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), ROUTE_SCAN)
            .onopen([&](crow::websocket::connection &conn) {})
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t)
                     { ; })
            .onmessage([&](crow::websocket::connection & /*conn*/, const std::string &data, bool is_binary)
                       {
                if (is_binary)
                    ;
                else
                    ; });
    }
};