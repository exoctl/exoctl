#include <cstdint>
#include <engine/crowapp/bridge/bridge.hxx>
#include <engine/crowapp/exception.hxx>
#include <engine/disassembly/capstone/exception.hxx>
#include <engine/parser/json.hxx>
#include <engine/security/yara/exception.hxx>

namespace crowapp
{
    Bridge::Bridge(CrowApp &p_crowapp) : m_crowapp(p_crowapp)
    {
        m_analysis = std::make_unique<bridge::Analysis>(m_crowapp);
        m_data = std::make_unique<bridge::Data>(m_crowapp);
        m_rev = std::make_unique<bridge::Rev>(m_crowapp);
        m_parser = std::make_unique<bridge::Parser>(m_crowapp);
    }

    Bridge::~Bridge()
    {
    }

    // DEFINE_ROUTE(PARSER_ELF, "/parser", "/binary", "/elf")
    // void Bridge::parser_elf()
    //{
    //     m_parser_elf = std::make_unique<focades::parser::binary::ELF>();
    //
    //    m_socket_parser_elf = std::make_unique<bridge::WebSocket>(
    //        m_crow,
    //        ROUTE_PARSER_ELF,
    //        UINT64_MAX,
    //        [&](bridge::websocket::Context &p_context,
    //            crow::websocket::connection &p_conn,
    //            const std::string &p_data,
    //            bool p_is_binary) {
    //            m_parser_elf->parser_bytes(
    //                "/usr/bin/ls",
    //                [&](focades::parser::binary::elf::record::DTO *p_dto) {
    //                    p_context.broadcast(
    //                        &p_conn,
    //                        m_parser_elf->dto_json(p_dto).to_string());
    //                });
    //        });
    //}

    void Bridge::load()
    {
        LOG(m_crowapp.get_log(), info, "Loading Gateways ... ");
        
        TRY_BEGIN()

        m_data->load();
        m_parser->load();
        m_rev->load();
        m_analysis->load();

        TRY_END()
        CATCH(std::bad_alloc, {
            LOG(m_crowapp.get_log(), error, "{}", e.what());
            throw exception::Abort(e.what());
        })
        CATCH(std::runtime_error, {
            LOG(m_crowapp.get_log(), error, "{}", e.what());
            throw exception::Abort(e.what());
        })
        CATCH(std::exception, {
            LOG(m_crowapp.get_log(), warn, "{}", e.what());
            throw exception::ParcialAbort(e.what());
        })
    }

    const std::vector<bridge::record::Bridge> &Bridge::get_endpoints()
    {
        // Bridge::update_endpoints();
        return m_endpoints;
    }

    // void Bridge::update_endpoints()
    //{
    // m_endpoints.clear();
    //
    // m_endpoints.emplace_back(
    //    ROUTE_SCAN_YARA,
    //    bridge::type::Bridge::websocket,
    //    m_socket_scan_yara->size_connections());
    //
    // m_endpoints.emplace_back(
    //    ROUTE_METADATA,
    //    bridge::type::Bridge::websocket,
    //    m_socket_metadata->size_connections());
    //
    // m_endpoints.emplace_back(
    //    ROUTE_CAPSTONE_DISASS_X86_64,
    //    bridge::type::Bridge::websocket,
    //    m_socket_capstone_disass_x86_64->size_connections());
    //
    // m_endpoints.emplace_back(
    //    ROUTE_CAPSTONE_DISASS_ARM64,
    //    bridge::type::Bridge::websocket,
    //    m_socket_capstone_disass_arm_64->size_connections());
    //
    // m_endpoints.emplace_back(
    //    ROUTE_PARSER_ELF,
    //    bridge::type::Bridge::websocket,
    //    m_socket_parser_elf->size_connections());
    //
    // m_endpoints.emplace_back(ROUTE_SCAN_CLAMAV,
    //                         bridge::type::Bridge::websocket,
    //                         m_socket_clamav->size_connections());
    //
    // m_endpoints.shrink_to_fit();
    // }
} // namespace crowapp
