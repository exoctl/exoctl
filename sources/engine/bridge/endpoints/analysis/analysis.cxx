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
        plugins::Plugins::lua.state
            .new_usertype<bridge::endpoints::analysis::Analysis>(
                "EndpointAnalysis",
                "analysis",
                &bridge::endpoints::analysis::Analysis::analysis);

        focades::analysis::Analysis::plugins();
    }

    void Analysis::setup(server::Server &p_server)
    {
        m_server = &p_server;
        m_enable = m_server->config->get("bridge.endpoint.analysis.enable")
                       .value<bool>()
                       .value();

        if (!m_enable) {
            m_server->log->warn("Gateway 'Analysis' not enabled");
            return;
        }

        analysis.setup(*m_server->config, *m_server->log);

        min_binary_size =
            m_server->config
                ->get("bridge.endpoint.analysis.scan.min_binary_size")
                .value<size_t>()
                .value();

        Analysis::scan();
        Analysis::records();
        Analysis::scan_threats();
    }

    void Analysis::load() const
    {
        if (!m_enable) {
            return;
        }

        analysis.load();
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

                        focades::analysis::record::File file;
                        file.content.assign(std::move(req.body));
                        file.owner.assign(req.remote_ip_address);

                        focades::analysis::record::Analysis anal;
                        TRY_BEGIN()
                        anal = analysis.scan(file);
                        analysis.file_write({anal.sha256, file.content});
                        if (analysis.table_exists_by_sha256(anal)) {
                            analysis.table_update(anal);
                        } else {
                            analysis.table_insert(anal);
                        }
                        TRY_END()
                        CATCH(focades::analysis::exception::Scan,
                              return crow::response{server::gateway::responses::
                                                        InternalServerError()
                                                            .code()};)

                        auto accept =
                            server::gateway::responses::Accepted().add_field(
                                "sha256", anal.sha256);

                        return crow::response{accept.code(),
                                              "application/json",
                                              accept.tojson().tostring()};
                    }

                    auto bad_requests =
                        server::gateway::responses::BadRequests().add_field(
                            "message",
                            fmt::format("File too small for scan minimal {}b",
                                        min_binary_size));

                    return crow::response{bad_requests.code(),
                                          "application/json",
                                          bad_requests.tojson().tostring()};
                });
        });
    }

    void Analysis::records()
    {
        m_map.add_route("/records", [&]() {
            m_web_records = std::make_unique<server::gateway::web::Web>();
            m_web_records->setup(
                &*m_server,
                BASE_ANALYSIS "/records",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::GET) {
                        auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    auto analyses = analysis.table_get_all();
                    parser::json::Json json;
                    for (const auto &anal : analyses) {
                        parser::json::Json record;
                        record.add("id", anal.id);
                        record.add("file_name", anal.file_name);
                        record.add("file_type", anal.file_type);
                        record.add("sha256", anal.sha256);
                        record.add("sha1", anal.sha1);
                        record.add("sha512", anal.sha512);
                        record.add("sha224", anal.sha224);
                        record.add("sha384", anal.sha384);
                        record.add("sha3_256", anal.sha3_256);
                        record.add("sha3_512", anal.sha3_512);
                        record.add("file_size", anal.file_size);
                        record.add("file_entropy", anal.file_entropy);
                        record.add("creation_date", anal.creation_date);
                        record.add("last_update_date", anal.last_update_date);
                        record.add("file_path", anal.file_path);
                        record.add("is_malicious", anal.is_malicious);
                        record.add("is_packed", anal.is_packed);
                        record.add("owner", anal.owner);
                        json.add(record);
                    }

                    auto connected =
                        server::gateway::responses::Connected().add_field(
                            "records", json);
                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });
    }

    void Analysis::scan_threats()
    {
        m_map.add_route("/scan/threats", [&]() {
            m_web_scan_threats = std::make_unique<server::gateway::web::Web>();
            m_web_scan_threats->setup(
                &*m_server,
                BASE_ANALYSIS "/scan/threats",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    parser::json::Json body;
                    body.from_string(req.body);

                    const auto &sha256 = body.get<std::string>("sha256");
                    if (sha256 == std::nullopt) {
                        auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                fmt::format("Field 'sha256' not found",
                                            min_binary_size));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    parser::json::Json json;

                    TRY_BEGIN()
                    focades::analysis::record::File file;
                    file.filename = sha256.value();
                    analysis.file_read(file);

                    analysis.scan_av_clamav->scan(
                        file.content,
                        [&](focades::analysis::scan::av::clamav::record::DTO
                                *p_dto) {
                            json.add(
                                "clamav",
                                std::move(
                                    analysis.scan_av_clamav->dto_json(p_dto)));
                        });

                    analysis.scan_yara->scan(
                        file.content,
                        [&](focades::analysis::scan::yara::record::DTO *p_dto) {
                            json.add(
                                "yara",
                                std::move(analysis.scan_yara->dto_json(p_dto)));
                        });
                    TRY_END()
                    CATCH(security::av::clamav::exception::Scan,
                          return crow::response{
                              server::gateway::responses::InternalServerError()
                                  .code()};)
                    CATCH(security::yara::exception::Scan,
                          return crow::response{
                              server::gateway::responses::InternalServerError()
                                  .code()};)

                    auto connected =
                        server::gateway::responses::Connected().add_field(
                            "threats", json);

                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });
    }
} // namespace engine::bridge::endpoints::analysis
