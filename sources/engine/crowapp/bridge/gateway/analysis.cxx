#include <engine/crowapp/bridge/gateway/analysis.hxx>
#include <engine/crowapp/exception.hxx>
#include <engine/logging.hxx>
#include <engine/security/yara/exception.hxx>
#include <stdint.h>

namespace crowapp
{
    namespace bridge
    {
        Analysis::Analysis(CrowApp &p_crow)
            : m_crowapp(p_crow), m_map(BASE_ANALYSIS)
        {
            LOG(m_crowapp.get_log(),
                info,
                "Preparing gateway analysis routes ...");
            Analysis::prepare();

            // add new routes
            Analysis::scan();
            Analysis::scan_yara();
            Analysis::scan_av_clamav();
        }

        Analysis::~Analysis()
        {
        }

        void Analysis::scan()
        {
            m_map.add_route("/scan", [&]() {
                m_socket_scan = std::make_unique<gateway::WebSocket>(
                    m_crowapp,
                    BASE_ANALYSIS "/scan",
                    UINT64_MAX,
                    [&](gateway::websocket::Context &p_context,
                        crow::websocket::connection &p_conn,
                        const std::string &p_data,
                        bool p_is_binary) {
                        parser::Json json;

                        m_scan_yara->scan_fast_bytes(
                            p_data,
                            [&](focades::analysis::scan::yara::record::DTO
                                    *p_dto) {
                                json.add_member_json(
                                    "yara", m_scan_yara->dto_json(p_dto));
                            });

                        m_scan_av_clamav->scan_fast_bytes(
                            "/home/mob/Downloads/"
                            "ROTEIRO_DE_SISTEMAS_DIGITAIS.pdf",
                            [&](focades::analysis::scan::av::clamav::record::DTO
                                    *p_dto) {
                                json.add_member_json(
                                    "av/clamav",
                                    m_scan_av_clamav->dto_json(p_dto));
                            });

                        p_context.broadcast(&p_conn, json.to_string());
                    });
            });
        }

        void Analysis::scan_av_clamav()
        {
            m_map.add_route("/scan/av/clamav", [&]() {
                m_socket_scan_av_clamav = std::make_unique<gateway::WebSocket>(
                    m_crowapp,
                    BASE_ANALYSIS "/scan/av/clamav",
                    UINT64_MAX,
                    [&](gateway::websocket::Context &p_context,
                        crow::websocket::connection &p_conn,
                        const std::string &p_data,
                        bool p_is_binary) {
                        m_scan_av_clamav->scan_fast_bytes(
                            "/home/mob/Downloads/"
                            "ROTEIRO_DE_SISTEMAS_DIGITAIS.pdf",
                            [&](focades::analysis::scan::av::clamav::record::DTO
                                    *p_dto) {
                                p_context.broadcast(
                                    &p_conn,
                                    m_scan_av_clamav->dto_json(p_dto)
                                        .to_string());
                            });
                    });
            });
        }

        void Analysis::scan_yara()
        {
            m_map.add_route("/scan/yara", [&]() {
                m_socket_scan_yara = std::make_unique<gateway::WebSocket>(
                    m_crowapp,
                    BASE_ANALYSIS "/scan/yara",
                    UINT64_MAX,
                    [&](gateway::websocket::Context &p_context,
                        crow::websocket::connection &p_conn,
                        const std::string &p_data,
                        bool p_is_binary) {
                        m_scan_yara->scan_fast_bytes(
                            p_data,
                            [&](focades::analysis::scan::yara::record::DTO
                                    *p_dto) {
                                p_context.broadcast(
                                    &p_conn,
                                    m_scan_yara->dto_json(p_dto).to_string());
                            });
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
            m_scan_yara = std::make_unique<focades::analysis::scan::Yara>(
                m_crowapp.get_config());
            m_scan_av_clamav =
                std::make_unique<focades::analysis::scan::av::Clamav>(
                    m_crowapp.get_config());

            TRY_BEGIN()
            LOG(m_crowapp.get_log(), info, "Loading rules yara ...");
            m_scan_yara->load_rules([&](uint64_t p_total_rules) {
                LOG(m_crowapp.get_log(),
                    info,
                    "Successfully loaded rules. Total Yara rules "
                    "count: "
                    "{:d}",
                    p_total_rules);
            });

            LOG(m_crowapp.get_log(), info, "Loading rules clamav ...");
            m_scan_av_clamav->load_rules([&](unsigned int p_total_rules) {
                LOG(m_crowapp.get_log(),
                    info,
                    "Successfully loaded rules. Total Clamav rules "
                    "count: "
                    "{:d}",
                    p_total_rules);
            });
            TRY_END()
            CATCH(security::yara::exception::LoadRules, {
                LOG(m_crowapp.get_log(), error, "{}", e.what());
                throw crowapp::exception::Abort(e.what());
            })
        }
    } // namespace bridge
} // namespace crowapp