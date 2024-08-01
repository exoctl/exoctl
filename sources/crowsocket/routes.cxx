#define CROW_ENFORCE_WS_SPEC

#include "routes.hxx"
#include "rnames.hxx"
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

    void Routes::create_routes()
    {
        GET_ROUTE(search);
        GET_ROUTE(scan);
    }

    void Routes::route_search()
    {

        CROW_WEBSOCKET_ROUTE(m_crow.get_app(), ROUTE_SEARCH)
            .onerror([&](crow::websocket::connection& conn, const std::string& error_message)
                {
                    
                })
            .onaccept([&](const crow::request &req, void **userdata)
                { 
                    return true; 
                })
            .onopen([&](crow::websocket::connection &conn)
                {
                    m_context.add_conn(conn);
                    m_context.send_msg(conn.get_remote_ip(), "Connection with your ip '" + conn.get_remote_ip() + "' Opened...\n"); 
                })
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t with_status_code)
                { 
                    m_context.remove_conn(conn);
                })
            .onmessage([&](crow::websocket::connection &conn, const std::string &data, bool is_binary)
                {
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

        CROW_WEBSOCKET_ROUTE(m_crow.get_app(), ROUTE_SCAN)
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