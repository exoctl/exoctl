#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <stdint.h>

namespace engine::bridge::endpoints::analysis
{
    Analysis::Analysis()
        : min_binary_size(0), m_map(BASE_ANALYSIS), m_enable(true)
    {
    }

    void Analysis::_plugins()
    {
        focades::analysis::Analysis::plugins();
    }

    void Analysis::setup(server::Server &p_server)
    {
        m_server = &p_server;
        m_enable = m_server->config->get("bridge.endpoint.analysis.enable")
                       .value<bool>()
                       .value();

        if (!m_enable) {
            m_server->log->warn("Gateway analysis not enabled");
            return;
        }

        m_analysis.setup(*m_server->config, *m_server->log);

        min_binary_size =
            m_server->config
                ->get("bridge.endpoint.analysis.scan.min_binary_size")
                .value<size_t>()
                .value();

        scan();
        // scan_yara();
        // scan_av_clamav();
    }

    void Analysis::load() const
    {
        if (!m_enable) {
            return;
        }

        m_analysis.load();
        m_map.get_routes(
            [&](const std::string p_route) { m_map.call_route(p_route); });
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
                        auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    if (!req.body.empty() &&
                        req.body.size() >= min_binary_size) {
                        focades::analysis::record::EnqueueTask task{
                            0, std::move(req.body)};

                        TRY_BEGIN()
                        m_analysis.enqueue_scan(task);
                        TRY_END()
                        CATCH(focades::analysis::exception::EnqueueScan,
                              return crow::response{server::gateway::responses::
                                                        InternalServerError()
                                                            .code()};)

                        auto accept =
                            server::gateway::responses::Accepted().add_field(
                                "task_id", task.id);

                        return crow::response{accept.code(),
                                              "application/json",
                                              accept.tojson().tostring()};
                    }

                    auto bad_requests =
                        server::gateway::responses::BadRequests().add_field(
                            "details",
                            fmt::format("File too small for scan minimal {}b",
                                        min_binary_size));

                    return crow::response{bad_requests.code(),
                                          "application/json",
                                          bad_requests.tojson().tostring()};
                });
        });
    }

    // void Analysis::scan_av_clamav()
    // {
    //     m_map.add_route("/scan/av/clamav", [&]() {
    //         m_web_scan_av_clamav =
    //             std::make_unique<server::gateway::web::Web>();
    //         m_web_scan_av_clamav->setup(
    //             &*m_server,
    //             BASE_ANALYSIS "/scan/av/clamav",
    //             [&](const crow::request &req) -> const crow::response {
    //                 if (req.method != crow::HTTPMethod::POST) {
    //                     auto method_not_allowed =
    //                         server::gateway::responses::MethodNotAllowed();
    //                     return crow::response{
    //                         method_not_allowed.code(),
    //                         "application/json",
    //                         method_not_allowed.tojson().tostring()};
    //                 }

    //                 parser::Json json;

    //                 TRY_BEGIN()
    //                 m_scan_av_clamav->scan(
    //                     req.body,
    //                     [&](focades::analysis::scan::av::clamav::record::DTO
    //                             *p_dto) {
    //                         json =
    //                         std::move(m_scan_av_clamav->dto_json(p_dto));
    //                     });
    //                 TRY_END()
    //                 CATCH(security::av::clamav::exception::Scan,
    //                       return crow::response{
    //                           server::gateway::responses::InternalServerError()
    //                               .code()};)

    //                 auto connected =
    //                     server::gateway::responses::Connected().add_field(
    //                         "clamav", json);

    //                 return crow::response{connected.code(),
    //                                       "application/json",
    //                                       connected.tojson().tostring()};
    //             });
    //     });
    // }

    // void Analysis::scan_yara()
    // {
    //     m_map.add_route("/scan/yara", [&]() {
    //         m_web_scan_yara = std::make_unique<server::gateway::web::Web>();
    //         m_web_scan_yara->setup(
    //             &*m_server,
    //             BASE_ANALYSIS "/scan/yara",
    //             [&](const crow::request &req) -> crow::response {
    //                 if (req.method != crow::HTTPMethod::POST) {
    //                     auto method_not_allowed =
    //                         server::gateway::responses::MethodNotAllowed();
    //                     return crow::response{
    //                         method_not_allowed.code(),
    //                         "application/json",
    //                         method_not_allowed.tojson().tostring()};
    //                 }

    //                 parser::Json json;
    //                 TRY_BEGIN()
    //                 m_scan_yara->scan(
    //                     req.body,
    //                     [&](focades::analysis::scan::yara::record::DTO
    //                     *p_dto) {
    //                         json = std::move(m_scan_yara->dto_json(p_dto));
    //                     });
    //                 TRY_END()
    //                 CATCH(security::yara::exception::Scan,
    //                       return crow::response{
    //                           server::gateway::responses::InternalServerError()
    //                               .code()};)

    //                 auto connected =
    //                     server::gateway::responses::Connected().add_field(
    //                         "yara", json);

    //                 return crow::response{connected.code(),
    //                                       "application/json",
    //                                       connected.tojson().tostring()};
    //             });
    //     });
    // }

} // namespace engine::bridge::endpoints::analysis
