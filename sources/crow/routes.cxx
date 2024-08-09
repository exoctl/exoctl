#include "routes.hxx"
#include "endpoints.hxx"
#include "iscan.hxx"
#include "scan.hxx"
#include "conn.hxx"

#include <optional>
#include <alloca.h>

namespace Crow
{
    Routes::Routes(Crow &p_crow) : m_crow(p_crow)
    {
    }

    Routes::~Routes()
    {
    }

    void Routes::routes_create()
    {
        GET_ROUTE(search);
        CROW_LOG_INFO << "Created route '" << ROUTE_SEARCH << "' websocket";

        GET_ROUTE(scan);
        CROW_LOG_INFO << "Created route '" << ROUTE_SCAN << "' websocket";
    }

    void Routes::route_search()
    {
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
        CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), ROUTE_SCAN)
            .onaccept([&](const crow::request &req, void **userdata)
                      { 
                        /* TODO: Create validator for check if sucessful connection */
                        return true; })
            .onopen([&](crow::websocket::connection &conn)
                    { SOCKET_OPEN_CONNECTION_CONTEXT })
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t)
                     { SOCKET_CLOSE_CONNECTION_CONTEXT })
            .onmessage([&](crow::websocket::connection &p_conn, const std::string &p_data, bool is_binary)
                       {
                    Analysis::IScan *scan = new Analysis::Scan(m_crow.crow_get_config());
                    
                    scan->load_rules([&](void *){ /**/ });

                    scan->scan_bytes(p_data, [&](void *p_callback_data)
                    {
                        CROW_LOG_INFO << "Scan '"  <<  m_context.conn_get_remote_ip(&p_conn) << "' finished in " << p_data.size() << "b";

                        const bool is_yara = (Analysis::yr_user_data *)p_callback_data != nullptr;
                        const std::string is_malicius = (is_yara) ? (((Analysis::yr_user_data *)p_callback_data)->is_malicius == malicious) 
                            ? "1" : "0" : "None";
                            
                        const auto rule = [&]() -> std::optional<const std::string> {
                                if (((Analysis::yr_user_data *)p_callback_data)->rule != nullptr) 
                                    return ((Analysis::yr_user_data *)p_callback_data)->rule;
                                
                                return "None";
                            }();
                        
                        
                        m_context.conn_send_msg(&p_conn,  "{\"is_malicius\":"+is_malicius+","
                                                        "\"rule\":\"" + rule.value() + "\"}");
                    });

                    delete scan; });
    }
};