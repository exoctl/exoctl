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
        CROW_LOG_INFO << "Created route '" << ROUTE_SEARCH << "' websocket";

        CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), ROUTE_SEARCH)
            .onerror([&](crow::websocket::connection &conn, const std::string &error_message) {

            })
            .onaccept([&](const crow::request &req, void **userdata)
                      { 
                        /* TODO: Create validator for check if sucessful connection */
                        return true; })
            .onopen([&](crow::websocket::connection &conn)
                    { SOCKET_OPEN_CONNECTION_CONTEXT })
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t with_status_code)
                     { SOCKET_CLOSE_CONNECTION_CONTEXT })
            .onmessage([&](crow::websocket::connection &conn, const std::string &data, bool is_binary)
                       {
                        std::lock_guard<std::mutex> _(m_mtx);
                        if (is_binary)
                        {
                        }else
                        {
                        } });
    }

    void Routes::route_scan()
    {
        CROW_LOG_INFO << "Created route '" << ROUTE_SCAN << "' websocket";

        Analysis::SYara *scan = new Analysis::SYara;

        scan->load_rules([&](void *)
                         {
            std::string rule = "rule binaryObfuscation { strings: $re0 = /=[0-1,]{512}/ condition: all of them }";
            scan->syara_set_signature_rule_mem(rule);
            scan->syara_load_rules_folder("rules/yara"); });

        CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), ROUTE_SCAN)
            .onopen([&](crow::websocket::connection &conn)
                    { SOCKET_OPEN_CONNECTION_CONTEXT })
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t)
                     { SOCKET_CLOSE_CONNECTION_CONTEXT })
            .onmessage([&](crow::websocket::connection & /*conn*/, const std::string &data, bool is_binary)
                       {
                if (is_binary)
                    ;
                else
                    ; });
    }
};