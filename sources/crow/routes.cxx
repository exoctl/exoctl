#include "analysis.hxx"
#include "conn.hxx"
#include "endpoints.hxx"
#include "routes.hxx"
#include "scan.hxx"

#include <alloca.h>
#include <optional>

namespace Crow
{
Routes::Routes(Crow &p_crow)
    : m_crow(p_crow), m_context(p_crow.crow_get_config())
{
    LOG(m_crow.crow_get_log(), info, "Routes initialized.");
}

Routes::~Routes() {}

void Routes::routes_create()
{
    GET_ROUTE(search);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for search: {}",
        ROUTE_SEARCH);

    GET_ROUTE(scan);
    LOG(m_crow.crow_get_log(), info, "Route created for scan: {}", ROUTE_SCAN);
}

void Routes::route_search()
{
    CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), ROUTE_SEARCH)
        .onerror(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_error_message)
            {
                LOG(m_crow.crow_get_log(),
                    error,
                    "WebSocket error on route '{}': {}",
                    ROUTE_SEARCH,
                    p_error_message);
            })
        .onaccept([&](const crow::request &p_req, void ** /*p_userdata*/)
                  { return Routes::route_def_onaccept_connection(&p_req); })
        .onopen([&](crow::websocket::connection &conn)
                { Routes::route_def_open_connection(&conn); })
        .onclose([&](crow::websocket::connection &p_conn,
                     const std::string &p_reason,
                     uint16_t /*status_code*/)
                 { Routes::route_def_close_connection(&p_conn, p_reason); })
        .onmessage(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary)
            {
                LOG(m_crow.crow_get_log(),
                    debug,
                    "Message received on route '{}': data size = {}",
                    ROUTE_SEARCH,
                    p_data.size());
            });
}

void Routes::route_scan()
{
    CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), ROUTE_SCAN)
        .onaccept([&](const crow::request &p_req, void ** /*p_userdata*/)
                  { return Routes::route_def_onaccept_connection(&p_req); })
        .onopen([&](crow::websocket::connection &conn)
                { Routes::route_def_open_connection(&conn); })
        .onclose([&](crow::websocket::connection &p_conn,
                     const std::string &p_reason,
                     uint16_t /*p_status_code*/)
                 { Routes::route_def_close_connection(&p_conn, p_reason); })
        .onmessage(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary)
            {
                LOG(m_crow.crow_get_log(),
                    debug,
                    "Message received on route '{}': data size = {}",
                    ROUTE_SCAN,
                    p_data.size());

                Analysis::Scan *scan =
                    new Analysis::Scan(m_crow.crow_get_config());

                scan->load_rules(
                    [&](void *) { /**/ });

                scan->scan_bytes(p_data,
                                 [&](void *p_dto_analysis)
                                 {
                                     Analysis::DTOAnalysis *analysis =
                                         static_cast<Analysis::DTOAnalysis *>(
                                             p_dto_analysis);

                                     std::string result =
                                         std::to_string(analysis->is_malicious);
                                     m_context.conn_send_msg(&p_conn, result);

                                 });

                delete scan;
            });
}

void Routes::route_def_close_connection(crow::websocket::connection *p_conn,
                                        const std::string &p_reason)
{
    std::lock_guard<std::mutex> _(m_mtx);
    m_context.conn_erase(p_conn);
    LOG(m_crow.crow_get_log(),
        info,
        "Connection closed: reason = '{}'",
        p_reason);
}

void Routes::route_def_open_connection(crow::websocket::connection *p_conn)
{
    std::lock_guard<std::mutex> _(m_mtx);
    m_context.conn_add(p_conn);
    m_context.conn_send_msg(p_conn, "{\"status\": \"ready\"}");

    LOG(m_crow.crow_get_log(),
        info,
        "Connection opened from IP: {}",
        m_context.conn_get_remote_ip(p_conn));
}

bool Routes::route_def_onaccept_connection(const crow::request *p_req)
{
    if (m_context.conn_check_whitelist(p_req))
        return true;

    LOG(m_crow.crow_get_log(),
        warn,
        "Connection rejected from IP: {}",
        p_req->remote_ip_address);

    return false;
}

}; // namespace Crow
