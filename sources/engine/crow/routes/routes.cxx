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

    WebSocket *socket_scan_yara = new WebSocket(
        m_crow,
        Endpoints::ROUTE_SCAN_YARA,
        [&](Context &p_context,
            crow::websocket::connection &p_conn,
            const std::string &p_data,
            bool p_is_binary)
        {
            LOG(m_crow.crow_get_log(),
                debug,
                "Message received on route '{}': data size = {}",
                Endpoints::ROUTE_SCAN_YARA,
                p_data.size());

            m_scan_yara.yara_scan_bytes(p_data);
            p_context.conn_send_msg(&p_conn,
                                    m_scan_yara.dto_to_json().json_to_string());
        });

    WebSocket *socket_metadata = new WebSocket(
        m_crow,
        Endpoints::ROUTE_METADATA,
        [&](Context &p_context,
            crow::websocket::connection &p_conn,
            const std::string &p_data,
            bool p_is_binary)
        {
            LOG(m_crow.crow_get_log(),
                debug,
                "Message received on route '{}': data size = {}",
                Endpoints::ROUTE_METADATA,
                p_data.size());

            m_metadata.metadata_parse(p_data);
            p_context.conn_send_msg(&p_conn,
                                    m_metadata.dto_to_json().json_to_string());
        });

    WebSocket *socket_capstone_disass = new WebSocket(
        m_crow,
        Endpoints::ROUTE_CAPSTONE_DISASS_X86_64,
        [&](Context &p_context,
            crow::websocket::connection &p_conn,
            const std::string &p_data,
            bool p_is_binary)
        {
            LOG(m_crow.crow_get_log(),
                debug,
                "Message received on route '{}': data size = {}",
                Endpoints::ROUTE_CAPSTONE_DISASS_X86_64,
                p_data.size());

            if (!p_is_binary)
                p_context.conn_send_msg(&p_conn, "{\"status\": \"error\"}");

            try
            {
                m_capstonex86.capstonex86_disassembly(p_data);
            }
            catch (const Disassembly::CapstoneException::FailedDisassembly &e)
            {
                LOG(m_crow.crow_get_log(),
                    error,
                    "Disassembly failed on route '{}': data size = {}, "
                    "error: {}",
                    Endpoints::ROUTE_CAPSTONE_DISASS_X86_64,
                    p_data.size(),
                    e.what());
            }
        });
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