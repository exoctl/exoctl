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

        if (!p_server.config->get("bridge.endpoint.analysis.enable")
                 .value<bool>()
                 .value()) {
            m_server->log->warn("Gateway analysis not enabled");
            return;
        }

        m_scan_yara->setup(*m_server->config);
        m_scan_av_clamav->setup(*m_server->config);

        // add new HTTP routes (Web)
        Analysis::scan();
        Analysis::scan_yara();
        Analysis::scan_av_clamav();
    }

    void Analysis::_plugins()
    {
        focades::analysis::scan::yara::Yara::plugins();

        plugins::Plugins::lua.state.new_usertype<endpoints::Analysis>(
            "Analysis", "scan", &endpoints::Analysis::m_scan_yara);
    }

    void Analysis::scan()
    {
        m_map.add_route("/scan", [&]() {
            m_web_scan = std::make_unique<server::gateway::web::Web>();
            m_web_scan->setup(
                &*m_server,
                BASE_ANALYSIS "/scan",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        return crow::response{405};
                    }

                    parser::Json json;
                    parser::Json av;

                    // TRY_BEGIN()
                    // m_scan_av_clamav->scan_fast_bytes(
                    //     req.body,
                    //     [&](focades::analysis::scan::av::clamav::record::DTO
                    //             *p_dto) {
                    //         av.add("clamav",
                    //         m_scan_av_clamav->dto_json(p_dto));
                    //     });
                    //
                    // json.add("av", av);
                    // return crow::response{json.to_string()};
                    // TRY_END()
                    //
                    // CATCH(security::yara::exception::Scan, {
                    //    m_server->log->info("Error scan yara
                    //    '{}'", e.what()); return
                    //    crow::response{500, e.what()};
                    //});

                    return crow::response(200);
                });
        });
    }

    void Analysis::scan_av_clamav()
    {
        m_map.add_route("/scan/av/clamav", [&]() {
            m_web_scan_av_clamav =
                std::make_unique<server::gateway::web::Web>();
            m_web_scan_av_clamav->setup(
                &*m_server,
                BASE_ANALYSIS "/scan/av/clamav",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        return crow::response{405};
                    }

                    parser::Json json;

                    m_scan_av_clamav->scan(
                        req.body,
                        [&](focades::analysis::scan::av::clamav::record::DTO
                                *p_dto) {
                            json = m_scan_av_clamav->dto_json(p_dto);
                        });

                    return crow::response{"application/json", json.tostring()};
                });
        });
    }

    void Analysis::scan_yara()
    {
        m_map.add_route("/scan/yara", [&]() {
            m_web_scan_yara = std::make_unique<server::gateway::web::Web>();
            m_web_scan_yara->setup(
                &*m_server,
                BASE_ANALYSIS "/scan/yara",
                [&](const crow::request &req) -> crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        return crow::response{405};
                    }

                    // TRY_BEGIN()
                    // parser::Json json;

                    // Se quiser ativar depois:
                    // m_scan_yara->scan(
                    //     req.body,
                    //     [&](focades::analysis::scan::yara::record::DTO
                    //     *p_dto) {
                    //         json = m_scan_yara->dto_json(p_dto);
                    //     });

                    // return crow::response{json.to_string()};
                    // TRY_END()
                    // CATCH(security::yara::exception::Scan, {
                    //     m_server->log->info("Error scan yara '{}'",
                    //     e.what()); return crow::response{500, e.what()};
                    // });
                });
        });
    }

    void Analysis::load() const
    {
        if (m_server->config->get("bridge.endpoint.analysis.enable")
                .value<bool>()
                .value()) {
            TRY_BEGIN()
            m_server->log->info("Loading rules yara...");
            m_scan_yara->load_rules();

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
    }
} // namespace engine::bridge::endpoints
