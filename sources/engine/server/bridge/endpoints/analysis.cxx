#include <engine/logging/logging.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/bridge/endpoints/analysis.hxx>
#include <engine/server/exception.hxx>
#include <stdint.h>

namespace engine::server::bridge::endpoints
{
    Analysis::Analysis(Server &p_server)
        : m_server(p_server), m_map(BASE_ANALYSIS)
    {
        Analysis::prepare();

        // add new routes
        Analysis::scan();
        Analysis::scan_yara();
        Analysis::scan_av_clamav();
    }

    void Analysis::register_plugins()
    {
        m_scan_yara->register_plugins();
    }

    void Analysis::scan()
    {
        m_map.add_route("/scan", [&]() {
            m_socket_scan =
                std::make_unique<engine::server::gateway::WebSocket>();
            m_socket_scan->setup(
                m_server,
                BASE_ANALYSIS "/scan",
                UINT64_MAX,
                // on_message_callback
                [&](gateway::websocket::Context &p_context,
                    crow::websocket::connection &p_conn,
                    const std::string &p_data,
                    bool p_is_binary) {
                    parser::Json json;
                    parser::Json av;

                    TRY_BEGIN()
                    m_scan_yara->scan_fast_bytes(
                        p_data,
                        [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                            json.add_member_json("yara",
                                                 m_scan_yara->dto_json(p_dto));
                        });

                    m_scan_av_clamav->scan_fast_bytes(
                        p_data,
                        [&](focades::analysis::scan::av::clamav::record::DTO
                                *p_dto) {
                            av.add_member_json(
                                "clamav", m_scan_av_clamav->dto_json(p_dto));
                        });

                    json.add_member_json("av", av);
                    p_context.broadcast_text(&p_conn, json.to_string());

                    TRY_END()
                    CATCH(security::yara::exception::Scan, {
                        m_server.log->info("Error scan yara '{}'", e.what());
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
                m_server,
                BASE_ANALYSIS "/scan/av/clamav",
                UINT64_MAX,
                // on_message_callback
                [&](gateway::websocket::Context &p_context,
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
                m_server,
                BASE_ANALYSIS "/scan/yara/fast",
                UINT64_MAX,
                // on_message_callback
                [&](gateway::websocket::Context &p_context,
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
                        m_server.log->info("Error scan yara '{}'", e.what());
                    })
                });
        });
    }

    void Analysis::load() const
    {
        m_map.get_routes(
            [&](const std::string p_route) { m_map.call_route(p_route); });
    }

    void Analysis::prepare()
    {
        m_server.log->info("Preparing gateway analysis routes ...");

        m_scan_yara =
            std::make_unique<focades::analysis::scan::Yara>(*m_server.config);
        m_scan_av_clamav =
            std::make_unique<focades::analysis::scan::av::Clamav>(
                *m_server.config);

        TRY_BEGIN()
        m_server.log->info("Loading rules yara ...");
        m_scan_yara->load_rules([&](uint64_t p_total_rules) {
            m_server.log->info(
                "Successfully loaded rules. Total Yara rules count: "
                "{:d}",
                p_total_rules);
        });

        m_server.log->info("Loading rules clamav ...");
        m_scan_av_clamav->load_rules([&](unsigned int p_total_rules) {
            m_server.log->info(
                "Successfully loaded rules. Total Clamav rules count: "
                "{:d}",
                p_total_rules);
        });
        TRY_END()
        CATCH(security::yara::exception::LoadRules, {
            m_server.log->error("{}", e.what());
            throw server::exception::Abort(e.what());
        })
    }
} // namespace engine::server::bridge::endpoints