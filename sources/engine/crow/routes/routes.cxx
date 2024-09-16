#include <cstdint>
#include <engine/crow/crow_exception.hxx>
#include <engine/crow/routes/endpoints.hxx>
#include <engine/crow/routes/routes.hxx>
#include <engine/disassembly/capstone/capstone_exception.hxx>
#include <engine/security/yara/yara_exception.hxx>

namespace Crow
{
Routes::Routes(CrowApp &p_crow) : m_crow(p_crow) {}

Routes::~Routes()
{
    delete m_scan_yara;
    delete m_metadata;
    delete m_capstone_x86_64;
    delete m_capstone_arm_64;
    delete m_socket_scan_yara;
    delete m_socket_metadata;
    delete m_socket_capstone_disass_x86_64;
    delete m_socket_capstone_disass_arm_64;
}

void Routes::routes_init()
{
    LOG(m_crow.crow_get_log(), info, "Initializing Routes ... ");

    GET_ROUTE(metadata);
    GET_ROUTE(capstone_disass_x86_64);
    GET_ROUTE(capstone_disass_arm_64);
    GET_ROUTE(scan_yara);
}

DEFINE_ROUTE(
    CAPSTONE_DISASS_X86_64, "/rev", "/capstone", "/disassembly", "/x86_64")
void Routes::route_capstone_disass_x86_64()
{
    m_capstone_x86_64 = new Controllers::Rev::Capstone(CS_ARCH_X86, CS_MODE_64);

    m_socket_capstone_disass_x86_64 = new WebSocket(
        m_crow,
        ROUTE_CAPSTONE_DISASS_X86_64,
        UINT64_MAX,
        [&](Socket::Context &p_context,
            crow::websocket::connection &p_conn,
            const std::string &p_data,
            bool p_is_binary)
        {
            if (p_is_binary)
            {
                LOG(m_crow.crow_get_log(),
                    debug,
                    "Message received on route '{}': data size = {}",
                    ROUTE_CAPSTONE_DISASS_X86_64,
                    p_data.size());

                try
                {
                    m_capstone_x86_64->capstone_disassembly(p_data);
                    p_context.conn_broadcast(
                        &p_conn,
                        m_capstone_x86_64->dto_to_json().json_to_string());
                }
                catch (
                    const Disassembly::CapstoneException::FailedDisassembly &e)
                {
                    LOG(m_crow.crow_get_log(),
                        error,
                        "Disassembly failed on route '{}': data size = {}, "
                        "error: {}",
                        ROUTE_CAPSTONE_DISASS_X86_64,
                        p_data.size(),
                        e.what());
                }
            }
            else
            {
                p_context.conn_broadcast(&p_conn, "{\"status\": \"error\"}");
            }
        });
}

DEFINE_ROUTE(
    CAPSTONE_DISASS_ARM64, "/rev", "/capstone", "/disassembly", "/arm_64")
void Routes::route_capstone_disass_arm_64()
{
    m_capstone_arm_64 =
        new Controllers::Rev::Capstone(CS_ARCH_ARM64, CS_MODE_ARM);

    m_socket_capstone_disass_arm_64 = new WebSocket(
        m_crow,
        ROUTE_CAPSTONE_DISASS_ARM64,
        UINT64_MAX,
        [&](Socket::Context &p_context,
            crow::websocket::connection &p_conn,
            const std::string &p_data,
            bool p_is_binary)
        {
            if (p_is_binary)
            {
                LOG(m_crow.crow_get_log(),
                    debug,
                    "Message received on route '{}': data size = {}",
                    ROUTE_CAPSTONE_DISASS_ARM64,
                    p_data.size());

                try
                {
                    m_capstone_arm_64->capstone_disassembly(p_data);
                    p_context.conn_broadcast(
                        &p_conn,
                        m_capstone_arm_64->dto_to_json().json_to_string());
                }
                catch (
                    const Disassembly::CapstoneException::FailedDisassembly &e)
                {
                    LOG(m_crow.crow_get_log(),
                        error,
                        "Disassembly failed on route '{}': data size = {}, "
                        "error: {}",
                        ROUTE_CAPSTONE_DISASS_ARM64,
                        p_data.size(),
                        e.what());
                }
            }
            else
            {
                p_context.conn_broadcast(&p_conn, "{\"status\": \"error\"}");
            }
        });
}

DEFINE_ROUTE(SCAN_YARA, "/analysis", "/scan_yara")
void Routes::route_scan_yara()
{
    m_scan_yara = new Controllers::Analysis::ScanYara(m_crow.crow_get_config());

    try
    {
        m_scan_yara->yara_load_rules(
            [&](void *p_total_rules)
            {
                LOG(m_crow.crow_get_log(),
                    info,
                    "Successfully loaded rules. Total Yara rules "
                    "count: "
                    "{:d}",
                    (uint64_t) p_total_rules);
            });
    }
    catch (const Security::YaraException::LoadRules &e)
    {
        LOG(m_crow.crow_get_log(), error, "{}", e.what());
        throw CrowException::Abort(std::string(e.what()));
    }

    m_socket_scan_yara = new WebSocket(
        m_crow,
        ROUTE_SCAN_YARA,
        UINT64_MAX,
        [&](Socket::Context &p_context,
            crow::websocket::connection &p_conn,
            const std::string &p_data,
            bool p_is_binary)
        {
            LOG(m_crow.crow_get_log(),
                debug,
                "Message received on route '{}': data size = {}",
                ROUTE_SCAN_YARA,
                p_data.size());

            m_scan_yara->yara_scan_bytes(p_data);
            p_context.conn_broadcast(
                &p_conn, m_scan_yara->dto_to_json().json_to_string());
        });
}

DEFINE_ROUTE(METADATA, "/data", "/metadata")
void Routes::route_metadata()
{
    m_metadata = new Controllers::Data::Metadata();

    m_socket_metadata = new WebSocket(
        m_crow,
        ROUTE_METADATA,
        UINT64_MAX,
        [&](Socket::Context &p_context,
            crow::websocket::connection &p_conn,
            const std::string &p_data,
            bool p_is_binary)
        {
            LOG(m_crow.crow_get_log(),
                debug,
                "Message received on route '{}': data size = {}",
                ROUTE_METADATA,
                p_data.size());

            m_metadata->metadata_parse(p_data);
            p_context.conn_broadcast(
                &p_conn, m_metadata->dto_to_json().json_to_string());
        });
}
}; // namespace Crow