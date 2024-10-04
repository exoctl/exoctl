#include <cstdint>
#include <engine/crowapp/exception.hxx>
#include <engine/crowapp/bridge/bridge.hxx>
#include <engine/disassembly/capstone/exception.hxx>
#include <engine/parser/json.hxx>
#include <engine/security/yara/exception.hxx>

namespace crowapp
{
    Bridge::Bridge(CrowApp &p_crow) : m_crow(p_crow), m_num_endpoints(0)
    {
    }

    Bridge::~Bridge()
    {
    }

    DEFINE_ROUTE(
        CAPSTONE_DISASS_X86_64, "/rev", "/disassembly", "/capstone", "/x86_64")
    void Bridge::routes_capstone_disass_x86_64()
    {
        m_capstone_x86_64 =
            std::make_unique<focades::rev::disassembly::Capstone>(CS_ARCH_X86,
                                                                  CS_MODE_64);

        m_socket_capstone_disass_x86_64 = std::make_unique<crowapp::bridge::WebSocket>(
            m_crow,
            ROUTE_CAPSTONE_DISASS_X86_64,
            UINT64_MAX,
            [&](bridge::websocket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                if (p_is_binary) {
                    m_capstone_x86_64->capstone_disassembly(
                        p_data,
                        [&](focades::rev::disassembly::capstone::record::DTO *p_dto) {
                            p_context.context_broadcast(
                                &p_conn,
                                m_capstone_x86_64->capstone_dto_json(p_dto)
                                    .json_to_string());
                        });
                } else {
                    p_context.context_broadcast(&p_conn,
                                             "{\"status\": \"error\"}");
                }
            });
    }

    DEFINE_ROUTE(
        CAPSTONE_DISASS_ARM64, "/rev", "/disassembly", "/capstone", "/arm_64")
    void Bridge::routes_capstone_disass_arm_64()
    {
        m_capstone_arm_64 =
            std::make_unique<focades::rev::disassembly::Capstone>(CS_ARCH_ARM64,
                                                                  CS_MODE_ARM);

        m_socket_capstone_disass_arm_64 = std::make_unique<bridge::WebSocket>(
            m_crow,
            ROUTE_CAPSTONE_DISASS_ARM64,
            UINT64_MAX,
            [&](bridge::websocket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                if (p_is_binary) {

                    m_capstone_arm_64->capstone_disassembly(
                        p_data,
                        [&](focades::rev::disassembly::capstone::record::DTO *p_dto) {
                            p_context.context_broadcast(
                                &p_conn,
                                m_capstone_arm_64->capstone_dto_json(p_dto)
                                    .json_to_string());
                        });

                } else {
                    p_context.context_broadcast(&p_conn,
                                             "{\"status\": \"error\"}");
                }
            });
    }

    DEFINE_ROUTE(SCAN_CLAMAV, "/analysis", "/scan", "/clamav")
    void Bridge::routes_scan_clamav()
    {
        m_scan_clamav = std::make_unique<focades::analysis::scan::Clamav>(
            m_crow.crow_get_config());

        LOG(m_crow.crow_get_log(), info, "Loading rules database clamav ...");
        m_scan_clamav->clamav_load_rules([&](unsigned int p_total_rules) {
            LOG(m_crow.crow_get_log(),
                info,
                "Successfully loaded rules. Total Clamav rules "
                "count: "
                "{:d}",
                p_total_rules);
        });

        m_socket_clamav = std::make_unique<bridge::WebSocket>(
            m_crow,
            ROUTE_SCAN_CLAMAV,
            UINT64_MAX,
            [&](bridge::websocket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                m_scan_clamav->clamav_scan_fast_bytes(
                    "/home/mob/Downloads/ROTEIRO_DE_SISTEMAS_DIGITAIS.pdf",
                    [&](focades::analysis::scan::clamav::record::DTO *p_dto) {
                        p_context.context_broadcast(
                            &p_conn,
                            m_scan_clamav->clamav_dto_json(p_dto)
                                .json_to_string());
                    });
            });
    }

    DEFINE_ROUTE(SCAN_YARA, "/analysis", "/scan", "/yara")
    void Bridge::routes_scan_yara()
    {
        m_scan_yara = std::make_unique<focades::analysis::scan::Yara>(
            m_crow.crow_get_config());

        TRY_BEGIN()
        LOG(m_crow.crow_get_log(), info, "Loading rules yara ...");
        m_scan_yara->yara_load_rules([&](uint64_t p_total_rules) {
            LOG(m_crow.crow_get_log(),
                info,
                "Successfully loaded rules. Total Yara rules "
                "count: "
                "{:d}",
                p_total_rules);
        });
        TRY_END()
        CATCH(security::yara::exception::LoadRules, {
            LOG(m_crow.crow_get_log(), error, "{}", e.what());
            throw exception::Abort(e.what());
        })

        m_socket_scan_yara = std::make_unique<bridge::WebSocket>(
            m_crow,
            ROUTE_SCAN_YARA,
            UINT64_MAX,
            [&](bridge::websocket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                m_scan_yara->yara_scan_fast_bytes(
                    p_data,
                    [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                        p_context.context_broadcast(
                            &p_conn,
                            m_scan_yara->yara_dto_json(p_dto).json_to_string());
                    });
            });
    }

    DEFINE_ROUTE(PARSER_ELF, "/parser", "/binary", "/elf")
    void Bridge::routes_parser_elf()
    {
        m_parser_elf = std::make_unique<focades::parser::binary::ELF>();

        m_socket_parser_elf = std::make_unique<bridge::WebSocket>(
            m_crow,
            ROUTE_PARSER_ELF,
            UINT64_MAX,
            [&](bridge::websocket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                m_parser_elf->elf_parser_bytes(
                    "/usr/bin/ls",
                    [&](focades::parser::binary::elf::record::DTO *p_dto) {
                        p_context.context_broadcast(
                            &p_conn,
                            m_parser_elf->elf_dto_json(p_dto).json_to_string());
                    });
            });
    }

    DEFINE_ROUTE(METADATA, "/data", "/metadata")
    void Bridge::routes_metadata()
    {
        m_metadata = std::make_unique<focades::data::Metadata>();
        
        m_socket_metadata = std::make_unique<bridge::WebSocket>(
            m_crow,
            ROUTE_METADATA,
            UINT64_MAX,
            [&](bridge::websocket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                std::string data = std::move(p_data);
                data.erase(std::remove(data.begin(), data.end(), '\n'),
                           data.cend());

                m_metadata->metadata_parse(
                    data, [&](focades::data::metadata::record::DTO *p_dto) {
                        p_context.context_broadcast(
                            &p_conn,
                            m_metadata->metadata_dto_json(p_dto)
                                .json_to_string());
                    });
            });
    }

#ifdef DEBUG

    DEFINE_ROUTE(ROUTES, "/debug", "/endpoints")
    void Bridge::routes_endpoint()
    {
        m_web_endpoins = std::make_unique<bridge::Web<>>(
            m_crow, ROUTE_ROUTES, [&](const crow::request &p_req) {
                parser::Json endpoints;

                const auto &routes = Bridge::routes_get_endpoints();
                for (const auto &route : routes) {
                    parser::Json endpoint;
                    endpoint.json_add_member_string("path", route.path);
                    endpoint.json_add_member_int("type", route.type);
                    if (route.type == bridge::type::Bridge::websocket)
                        endpoint.json_add_member_int("connections",
                                                     route.connections);

                    endpoints.json_add_member_json(route.path, endpoint);
                }

                return endpoints.json_to_string();
            });
    }

#endif

    void Bridge::routes_init()
    {
        LOG(m_crow.crow_get_log(), info, "Initializing Routes ... ");
        TRY_BEGIN()
        GET_ROUTE(metadata);
        GET_ROUTE(capstone_disass_x86_64);
        GET_ROUTE(capstone_disass_arm_64);
        GET_ROUTE(scan_yara);
        GET_ROUTE(scan_clamav);
        GET_ROUTE(parser_elf);
#if DEBUG
        GET_ROUTE(endpoint);
#endif

        TRY_END()
        CATCH(std::bad_alloc, {
            LOG(m_crow.crow_get_log(), error, "{}", e.what());
            throw exception::Abort(e.what());
        })
        CATCH(std::runtime_error, {
            LOG(m_crow.crow_get_log(), error, "{}", e.what());
            throw exception::Abort(e.what());
        })
        CATCH(std::exception, {
            LOG(m_crow.crow_get_log(), warn, "{}", e.what());
            throw exception::ParcialAbort(e.what());
        })

        m_endpoints.reserve(m_num_endpoints);
    }

    const std::vector<bridge::record::Bridge> &Bridge::routes_get_endpoints()
    {
        Bridge::routes_update_endpoints();
        return m_endpoints;
    }

    void Bridge::routes_update_endpoints()
    {
        m_endpoints.clear();

        m_endpoints.emplace_back(
            ROUTE_SCAN_YARA,
            bridge::type::Bridge::websocket,
            m_socket_scan_yara->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_METADATA,
            bridge::type::Bridge::websocket,
            m_socket_metadata->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_CAPSTONE_DISASS_X86_64,
            bridge::type::Bridge::websocket,
            m_socket_capstone_disass_x86_64->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_CAPSTONE_DISASS_ARM64,
            bridge::type::Bridge::websocket,
            m_socket_capstone_disass_arm_64->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_PARSER_ELF,
            bridge::type::Bridge::websocket,
            m_socket_parser_elf->websocket_size_connections());

        m_endpoints.emplace_back(ROUTE_SCAN_CLAMAV,
                                 bridge::type::Bridge::websocket,
                                 m_socket_clamav->websocket_size_connections());

        m_endpoints.shrink_to_fit();
    }
} // namespace crowapp
