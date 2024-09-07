#include <alloca.h>
#include <engine/crow/conn/conn.hxx>
#include <engine/crow/crow_exception.hxx>
#include <engine/crow/routes/endpoints.hxx>
#include <engine/crow/routes/routes.hxx>
#include <engine/disassembly/capstone/capstone_exception.hxx>
#include <engine/security/yara/yara_exception.hxx>
#include <optional>

namespace Crow
{
Routes::Routes(CrowApp &p_crow)
    : m_crow(p_crow), m_context(p_crow.crow_get_config()),
      m_scan_yara(p_crow.crow_get_config())
{
}

Routes::~Routes() {}

void Routes::routes_init()
{
    Routes::route_init_analysis();

    LOG(m_crow.crow_get_log(), info, "Initializing Routes ... ");

    GET_ROUTE(search_yara);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for search_yara : {}",
        Endpoints::ROUTE_SEARCH_YARA);

    GET_ROUTE(scan_sig_packed);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for scan_packed : {}",
        Endpoints::ROUTE_SCAN_SIG_PACKED);

    GET_ROUTE(scan_yara);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for scan_yara : {}",
        Endpoints::ROUTE_SCAN_YARA);

    GET_ROUTE(metadata);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for metadata : {}",
        Endpoints::ROUTE_METADATA);

    GET_ROUTE(capstone_disassembly_x86_64);
    LOG(m_crow.crow_get_log(),
        info,
        "Route created for metadata : {}",
        Endpoints::ROUTE_CAPSTONE_DISASS_X86_64);
}

void Routes::route_scan_sig_packed()
{
    CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(),
                         Endpoints::ROUTE_SCAN_SIG_PACKED)
        .onerror(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_error_message)
            {
                LOG(m_crow.crow_get_log(),
                    error,
                    "WebSocket error on route '{}': {}",
                    Endpoints::ROUTE_SCAN_SIG_PACKED,
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
                    Endpoints::ROUTE_SCAN_SIG_PACKED,
                    p_data.size());
            });
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

                m_scan_yara.yara_scan_bytes(p_data);
                m_context.conn_send_msg(
                    &p_conn, m_scan_yara.dto_to_json().json_to_string());
            });
}

void Routes::route_metadata()
{
    CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(), Endpoints::ROUTE_METADATA)
        .onerror(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_error_message)
            {
                LOG(m_crow.crow_get_log(),
                    error,
                    "WebSocket error on route '{}': {}",
                    Endpoints::ROUTE_METADATA,
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
                    Endpoints::ROUTE_METADATA,
                    p_data.size());

                m_metadata.metadata_parse(p_data);
                m_context.conn_send_msg(
                    &p_conn, m_metadata.dto_to_json().json_to_string());
            });
}

void Routes::route_capstone_disassembly_x86_64()
{
    CROW_WEBSOCKET_ROUTE(m_crow.crow_get_app(),
                         Endpoints::ROUTE_CAPSTONE_DISASS_X86_64)
        .onerror(
            [&](crow::websocket::connection &p_conn,
                const std::string &p_error_message)
            {
                LOG(m_crow.crow_get_log(),
                    error,
                    "WebSocket error on route '{}': {}",
                    Endpoints::ROUTE_CAPSTONE_DISASS_X86_64,
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
                    Endpoints::ROUTE_CAPSTONE_DISASS_X86_64,
                    p_data.size());

                if (p_is_binary)
                {
                    try
                    {
                        m_capstonex86.capstonex86_disassembly(p_data);
                    }
                    catch (
                        const Disassembly::CapstoneException::FailedDisassembly
                            &e)
                    {
                        LOG(m_crow.crow_get_log(),
                            error,
                            "Disassembly failed on route '{}': data size = {}, "
                            "error: {}",
                            Endpoints::ROUTE_CAPSTONE_DISASS_X86_64,
                            p_data.size(),
                            e.what());
                    }
                }
                else
                {
                    m_context.conn_send_msg(&p_conn, "{\"status\": \"error\"}");
                }
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
    try
    {
        m_scan_yara.yara_load_rules(
            [&](void *p_total_rules)
            {
                LOG(m_crow.crow_get_log(),
                    info,
                    "Successfully loaded rules. Total Yara rules count: {:d}",
                    (uint64_t) p_total_rules);
            });
    }
    catch (const Security::YaraException::LoadRules &e)
    {
        LOG(m_crow.crow_get_log(), error, "{}", e.what());
        throw CrowException::Abort(std::string(e.what()));
    }
}

}; // namespace Crow
