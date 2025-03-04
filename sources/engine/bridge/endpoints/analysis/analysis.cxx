#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/yara/exception.hxx>
#include <stdint.h>

namespace engine::bridge::endpoints
{
    Analysis::Analysis()
        : m_map(BASE_ANALYSIS),
          m_scan_av_clamav(
              std::make_shared<focades::analysis::scan::av::clamav::Clamav>()),
          m_scan_yara(std::make_shared<focades::analysis::scan::yara::Yara>())
    {
    }

    void Analysis::setup(server::Server &p_server)
    {
        m_server = &p_server;

        m_scan_yara->setup(*m_server->config);
        m_scan_av_clamav->setup(*m_server->config);

        // add new routes
        Analysis::scan();
        Analysis::scan_yara();
        Analysis::scan_av_clamav();
    }

#ifdef ENGINE_PRO
    void Analysis::_plugins()
    {
        focades::analysis::scan::yara::Yara::plugins();
        
        plugins::Plugins::lua.state.new_usertype<endpoints::Analysis>(
            "Analysis", "scan", &endpoints::Analysis::m_scan_yara);
    }
#endif

    void Analysis::scan()
    {
        m_map.add_route("/scan", [&]() {
            m_socket_scan = std::make_unique<server::gateway::WebSocket>();
            m_socket_scan->setup(
                *m_server,
                BASE_ANALYSIS "/scan",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    parser::Json json;
                    parser::Json av;

                    TRY_BEGIN()
                    m_scan_yara->scan_fast_bytes(
                        p_data,
                        [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                            json.add("yara", m_scan_yara->dto_json(p_dto));
                        });

                    m_scan_av_clamav->scan_fast_bytes(
                        p_data,
                        [&](focades::analysis::scan::av::clamav::record::DTO
                                *p_dto) {
                            av.add("clamav", m_scan_av_clamav->dto_json(p_dto));
                        });

                    json.add("av", av);
                    p_context.broadcast_text(&p_conn, json.to_string());

                    TRY_END()
                    CATCH(security::yara::exception::Scan, {
                        m_server->log->info("Error scan yara '{}'", e.what());
                    })
                });
        });
    }

    void Analysis::scan_av_clamav()
    {
        m_map.add_route("/scan/av/clamav", [&]() {
            m_socket_scan_av_clamav =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_scan_av_clamav->setup(
                *m_server,
                BASE_ANALYSIS "/scan/av/clamav",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    m_scan_av_clamav->scan_fast_bytes(
                        p_data,
                        [&](focades::analysis::scan::av::clamav::record::DTO
                                *p_dto) {
                            p_context.broadcast_text(
                                &p_conn,
                                m_scan_av_clamav->dto_json(p_dto).to_string());
                        });
                });
        });
    }

    void Analysis::scan_yara()
    {
        m_map.add_route("/scan/yara/fast", [&]() {
            m_socket_scan_yara =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_scan_yara->setup(
                *m_server,
                BASE_ANALYSIS "/scan/yara/fast",
                UINT64_MAX,
                // on_message_callback
                [&](server::gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    TRY_BEGIN()
                    m_scan_yara->scan_fast_bytes(
                        p_data,
                        [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                            p_context.broadcast_text(
                                &p_conn,
                                m_scan_yara->dto_json(p_dto).to_string());
                        });
                    TRY_END()
                    CATCH(security::yara::exception::Scan, {
                        m_server->log->info("Error scan yara '{}'", e.what());
                    })
                });
        });
    }

    void Analysis::load() const
    {
        TRY_BEGIN()
        m_server->log->info("Loading rules yara ...");
        m_scan_yara->load_rules([&](uint64_t p_total_rules) {
            m_server->log->info(
                "Successfully loaded rules. Total Yara rules count: "
                "{:d}",
                p_total_rules);
        });

        m_server->log->info("Loading rules clamav ...");
        m_scan_av_clamav->load_rules([&](unsigned int p_total_rules) {
            m_server->log->info(
                "Successfully loaded rules. Total Clamav rules count: "
                "{:d}",
                p_total_rules);
        });
        TRY_END()
        CATCH(security::yara::exception::LoadRules, {
            m_server->log->error("{}", e.what());
            throw exception::Abort(e.what());
        })

        m_map.get_routes(
            [&](const std::string p_route) { m_map.call_route(p_route); });
    }
} // namespace engine::bridge::endpoints