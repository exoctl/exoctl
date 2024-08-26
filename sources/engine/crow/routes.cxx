#include <alloca.h>
#include <engine/crow/conn.hxx>
#include <engine/crow/endpoints.hxx>
#include <engine/crow/routes.hxx>
#include <optional>

namespace Crow
{
Routes::Routes(Crow &p_crow)
    : m_crow(p_crow), m_context(p_crow.crow_get_config()),
      m_scan_yara(p_crow.crow_get_config())
{
    Routes::route_init_analysis();
    LOG(m_crow.crow_get_log(), info, "Routes initialized.");
}

Routes::~Routes() {}

void Routes::routes_create()
{
    GET_ROUTE(search_yara);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for search: {}",
        Endpoints::ROUTE_SEARCH_YARA);

    GET_ROUTE(scan_yara);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for scan: {}",
        Endpoints::ROUTE_SCAN_YARA);
}

void Routes::route_search_yara()
{
    CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), Endpoints::ROUTE_SEARCH_YARA)
        .onerror(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_error_message)
            {
                LOG(m_crow.crow_get_log(),
                    error,
                    "WebSocket error on route '{}': {}",
                    Endpoints::ROUTE_SEARCH_YARA,
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
                    Endpoints::ROUTE_SEARCH_YARA,
                    p_data.size());
            });
}

void Routes::route_scan_yara()
{
    CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), Endpoints::ROUTE_SCAN_YARA)
        .onerror(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_error_message)
            {
                LOG(m_crow.crow_get_log(),
                    error,
                    "WebSocket error on route '{}': {}",
                    Endpoints::ROUTE_SCAN_YARA,
                    p_error_message);
            })
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
                    Endpoints::ROUTE_SCAN_YARA,
                    p_data.size());

                m_scan_yara.scan_yara_bytes(p_data);
                m_context.conn_send_msg(&p_conn, m_scan_yara.dto_to_json().json_to_string());
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
    std::lock_guard<std::mutex> _(m_mtx);
    if (m_context.conn_check_whitelist(p_req))
        return true;

    LOG(m_crow.crow_get_log(),
        warn,
        "Connection rejected from IP: {}",
        p_req->remote_ip_address);

    return false;
}

void Routes::route_init_analysis()
{
    m_scan_yara.load_yara_rules(
        [&](void *p_total_rules)
        {
            LOG(m_crow.crow_get_log(),
                info,
                "Successfully loaded rules. Total rules count: {:d}",
                (uint64_t) p_total_rules);
        });
}

}; // namespace Crow
