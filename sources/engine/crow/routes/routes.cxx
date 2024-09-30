#include <cstdint>
#include <engine/crow/crow_exception.hxx>
#include <engine/crow/routes/endpoints.hxx>
#include <engine/crow/routes/routes.hxx>
#include <engine/disassembly/capstone/capstone_exception.hxx>
#include <engine/parser/json.hxx>
#include <engine/security/yara/yara_exception.hxx>

namespace Crow
{
    Routes::Routes(CrowApp &p_crow) : m_crow(p_crow), m_num_endpoints(0)
    {
    }

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
        delete m_socket_parser_elf;
#if DEBUG
        delete m_web_endpoins;
#endif
    }

    DEFINE_ROUTE(
        CAPSTONE_DISASS_X86_64, "/rev", "/disassembly", "/capstone", "/x86_64")
    void Routes::routes_capstone_disass_x86_64()
    {
        m_capstone_x86_64 =
            new Focades::Rev::Disassembly::Capstone(CS_ARCH_X86, CS_MODE_64);

        m_socket_capstone_disass_x86_64 = new WebSocket(
            m_crow,
            ROUTE_CAPSTONE_DISASS_X86_64,
            UINT64_MAX,
            [&](Socket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                if (p_is_binary) {
                    LOG(m_crow.crow_get_log(),
                        debug,
                        "Message received on route '{}': data size = {}",
                        ROUTE_CAPSTONE_DISASS_X86_64,
                        p_data.size());

                    TRY_BEGIN()
                    m_capstone_x86_64->capstone_disassembly(
                        p_data,
                        [&](Focades::Rev::Disassembly::Structs::DTO *p_dto) {
                            p_context.conn_broadcast(
                                &p_conn,
                                m_capstone_x86_64->capstone_dto_json(p_dto)
                                    .json_to_string());
                        });
                    TRY_END()
                    CATCH(Disassembly::CapstoneException::FailedDisassembly, {
                        LOG(m_crow.crow_get_log(),
                            error,
                            "Disassembly failed on route '{}': data size = {}, "
                            "error: {}",
                            ROUTE_CAPSTONE_DISASS_X86_64,
                            p_data.size(),
                            e.what());
                    })
                } else {
                    p_context.conn_broadcast(&p_conn,
                                             "{\"status\": \"error\"}");
                }
            });
    }

    DEFINE_ROUTE(
        CAPSTONE_DISASS_ARM64, "/rev", "/disassembly", "/capstone", "/arm_64")
    void Routes::routes_capstone_disass_arm_64()
    {
        m_capstone_arm_64 =
            new Focades::Rev::Disassembly::Capstone(CS_ARCH_ARM64, CS_MODE_ARM);

        m_socket_capstone_disass_arm_64 = new WebSocket(
            m_crow,
            ROUTE_CAPSTONE_DISASS_ARM64,
            UINT64_MAX,
            [&](Socket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                if (p_is_binary) {
                    LOG(m_crow.crow_get_log(),
                        debug,
                        "Message received on route '{}': data size = {}",
                        ROUTE_CAPSTONE_DISASS_ARM64,
                        p_data.size());

                    TRY_BEGIN()
                    m_capstone_arm_64->capstone_disassembly(
                        p_data,
                        [&](Focades::Rev::Disassembly::Structs::DTO *p_dto) {
                            p_context.conn_broadcast(
                                &p_conn,
                                m_capstone_arm_64->capstone_dto_json(p_dto)
                                    .json_to_string());
                        });

                    TRY_END()
                    CATCH(Disassembly::CapstoneException::FailedDisassembly, {
                        LOG(m_crow.crow_get_log(),
                            error,
                            "Disassembly failed on route '{}': data size = {}, "
                            "error: {}",
                            ROUTE_CAPSTONE_DISASS_ARM64,
                            p_data.size(),
                            e.what());
                    })
                } else {
                    p_context.conn_broadcast(&p_conn,
                                             "{\"status\": \"error\"}");
                }
            });
    }

    DEFINE_ROUTE(SCAN_YARA, "/analysis", "/scan", "/yara")
    void Routes::routes_scan_yara()
    {
        m_scan_yara =
            new Focades::Analysis::Scan::Yara(m_crow.crow_get_config());

        TRY_BEGIN()
        m_scan_yara->scan_yara_load_rules([&](void *p_total_rules) {
            LOG(m_crow.crow_get_log(),
                info,
                "Successfully loaded rules. Total Yara rules "
                "count: "
                "{:d}",
                (uint64_t) p_total_rules);
        });
        TRY_END()
        CATCH(Security::YaraException::LoadRules, {
            LOG(m_crow.crow_get_log(), error, "{}", e.what());
            throw CrowException::Abort(e.what());
        })

        m_socket_scan_yara = new WebSocket(
            m_crow,
            ROUTE_SCAN_YARA,
            UINT64_MAX,
            [&](Socket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                LOG(m_crow.crow_get_log(),
                    debug,
                    "Message received on route '{}': data size = {}",
                    ROUTE_SCAN_YARA,
                    p_data.size());

                m_scan_yara->scan_yara_fast_bytes(
                    p_data, [&](Focades::Analysis::Scan::Structs::DTO *p_dto) {
                        p_context.conn_broadcast(
                            &p_conn,
                            m_scan_yara->scan_yara_dto_json(p_dto)
                                .json_to_string());
                    });
            });
    }

    DEFINE_ROUTE(PARSER_ELF, "/parser", "/binary", "/elf")
    void Routes::routes_parser_elf()
    {
        m_parser_elf = new Focades::Parser::Binary::ELF();

        m_socket_parser_elf = new WebSocket(
            m_crow,
            ROUTE_PARSER_ELF,
            UINT64_MAX,
            [&](Socket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                LOG(m_crow.crow_get_log(),
                    debug,
                    "Message received on route '{}': data size = {}",
                    ROUTE_PARSER_ELF,
                    p_data.size());

                m_parser_elf->elf_parser_bytes(
                    "/usr/bin/ls",
                    [&](Focades::Parser::Binary::Structs::DTO *p_dto) {
                        p_context.conn_broadcast(
                            &p_conn,
                            m_parser_elf->elf_dto_json(p_dto).json_to_string());
                    });
            });
    }

    DEFINE_ROUTE(METADATA, "/data", "/metadata")
    void Routes::routes_metadata()
    {
        m_metadata = new Focades::Data::Metadata();

        m_socket_metadata = new WebSocket(
            m_crow,
            ROUTE_METADATA,
            UINT64_MAX,
            [&](Socket::Context &p_context,
                crow::websocket::connection &p_conn,
                const std::string &p_data,
                bool p_is_binary) {
                LOG(m_crow.crow_get_log(),
                    debug,
                    "Message received on route '{}': data size = {}",
                    ROUTE_METADATA,
                    p_data.size());

                std::string data = std::move(p_data);
                data.erase(std::remove(data.begin(), data.end(), '\n'),
                           data.cend());
                m_metadata->metadata_parse(
                    data, [&](Focades::Data::Structs::DTO *p_dto) {
                        p_context.conn_broadcast(
                            &p_conn,
                            m_metadata->metadata_dto_json(p_dto)
                                .json_to_string());
                    });
            });
    }

#ifdef DEBUG

    DEFINE_ROUTE(ROUTES, "/debug", "/endpoints")
    void Routes::routes_endpoint()
    {
        m_web_endpoins =
            new Web<>(m_crow, ROUTE_ROUTES, [&](const crow::request &p_req) {
                Parser::Json endpoints;

                const auto &routes = Routes::routes_get_endpoints();
                for (const auto &route : routes) {
                    Parser::Json endpoint;
                    endpoint.json_add_member_string("path", route.path);
                    endpoint.json_add_member_int("type", route.type);
                    if (route.type == Types::Route::websocket)
                        endpoint.json_add_member_int("connections",
                                                     route.connections);

                    endpoints.json_add_member_json(route.path, endpoint);
                }

                return endpoints.json_to_string();
            });
    }

#endif

    void Routes::routes_update_endpoints()
    {
        m_endpoints.reserve(m_num_endpoints);
        m_endpoints.clear();

        m_endpoints.emplace_back(
            ROUTE_SCAN_YARA,
            Types::Route::websocket,
            m_socket_scan_yara->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_METADATA,
            Types::Route::websocket,
            m_socket_metadata->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_CAPSTONE_DISASS_X86_64,
            Types::Route::websocket,
            m_socket_capstone_disass_x86_64->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_CAPSTONE_DISASS_ARM64,
            Types::Route::websocket,
            m_socket_capstone_disass_arm_64->websocket_size_connections());

        m_endpoints.emplace_back(
            ROUTE_PARSER_ELF,
            Types::Route::websocket,
            m_socket_parser_elf->websocket_size_connections());

#if DEBUG
        m_endpoints.emplace_back(ROUTE_ROUTES, Types::Route::web, 0);
#endif
    }

    void Routes::routes_init()
    {
        LOG(m_crow.crow_get_log(), info, "Initializing Routes ... ");
        TRY_BEGIN()
        GET_ROUTE(metadata);
        GET_ROUTE(capstone_disass_x86_64);
        GET_ROUTE(capstone_disass_arm_64);
        GET_ROUTE(scan_yara);
        GET_ROUTE(parser_elf);
#if DEBUG
        GET_ROUTE(endpoint);
#endif
        TRY_END()
        CATCH(std::bad_alloc, {
            LOG(m_crow.crow_get_log(), error, "{}", e.what());
            throw CrowException::Abort(e.what());
        })
    }

    const std::vector<Structs::Endpoints> &Routes::routes_get_endpoints()
    {
        Routes::routes_update_endpoints();
        return m_endpoints;
    }
}; // namespace Crow