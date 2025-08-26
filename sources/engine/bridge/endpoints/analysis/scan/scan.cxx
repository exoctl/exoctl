#include <engine/bridge/endpoints/analysis/scan/scan.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <fmt/format.h>

namespace engine::bridge::endpoints::analysis
{
    void Scan::setup(Analysis &analysis)
    {
        analysis.map_.add_route("/scan", [&]() {
            analysis.web_scan_ = std::make_unique<server::gateway::web::Web>();
            analysis.web_scan_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/scan",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    if (!req.body.empty() &&
                        req.body.size() >= analysis.min_binary_size) {

                        focades::analysis::record::File file;
                        file.content.assign(std::move(req.body));
                        file.owner.assign(req.remote_ip_address);

                        focades::analysis::record::Analysis anal;
                        TRY_BEGIN()
                        anal = analysis.analysis.scan(file);
                        analysis.analysis.file_write({anal.sha256, file.content});
                        if (analysis.analysis.analysis_table_exists_by_sha256(anal)) {
                            analysis.analysis.analysis_table_update(anal);
                        } else {
                            analysis.analysis.analysis_table_insert(anal);
                        }
                        TRY_END()
                        CATCH(focades::analysis::exception::Scan,
                              return crow::response{server::gateway::responses::
                                                        InternalServerError()
                                                            .code()};)

                        const auto accept =
                            server::gateway::responses::Accepted().add_field(
                                "sha256", anal.sha256);

                        return crow::response{accept.code(),
                                              "application/json",
                                              accept.tojson().tostring()};
                    }

                    auto bad_requests =
                        server::gateway::responses::BadRequests().add_field(
                            "message",
                            fmt::format("File too small for "
                                        "scan minimal {}b",
                                        analysis.min_binary_size));

                    return crow::response{bad_requests.code(),
                                          "application/json",
                                          bad_requests.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/rescan", [&]() {
            analysis.web_scan_ = std::make_unique<server::gateway::web::Web>();
            analysis.web_scan_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/rescan",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    parser::json::Json body;
                    body.from_string(req.body);

                    const auto &sha256 = body.get<std::string>("sha256");
                    if (sha256 == std::nullopt || sha256->empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                "Field 'sha256' is missing or empty");
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    focades::analysis::record::Analysis new_anal;
                    focades::analysis::record::Analysis anal;

                    TRY_BEGIN()
                    anal = analysis.analysis.analysis_table_get_by_sha256(sha256.value());
                    if (anal.sha256.empty() ||
                        !filesystem::Filesystem::is_exists({sha256.value()})) {
                        const auto not_found =
                            server::gateway::responses::NotFound().add_field(
                                "message",
                                fmt::format("Record with sha256 '{}' not found",
                                            sha256.value()));
                        return crow::response{not_found.code(),
                                              "application/json",
                                              not_found.tojson().tostring()};
                    }

                    focades::analysis::record::File file;
                    file.filename = anal.sha256;
                    analysis.analysis.file_read(file);

                    new_anal = analysis.analysis.scan(file);
                    new_anal.id = anal.id;
                    new_anal.file_name = anal.file_name;
                    new_anal.family_id = (new_anal.family_id) != 0
                                             ? new_anal.family_id
                                             : anal.family_id;
                    new_anal.description = anal.description;

                    (analysis.analysis.analysis_table_exists_by_sha256(new_anal))
                        ? analysis.analysis.analysis_table_update(new_anal)
                        : analysis.analysis.analysis_table_insert(new_anal);

                    TRY_END()
                    CATCH(focades::analysis::exception::Scan,
                          return crow::response{
                              server::gateway::responses::InternalServerError()
                                  .code()};)

                    const auto accept =
                        server::gateway::responses::Accepted().add_field(
                            "sha256", new_anal.sha256);

                    return crow::response{accept.code(),
                                          "application/json",
                                          accept.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/scan/threats", [&]() {
            analysis.web_scan_threats_ = std::make_unique<server::gateway::web::Web>();
            analysis.web_scan_threats_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/scan/threats",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    parser::json::Json body;
                    body.from_string(req.body);

                    const auto &sha256 = body.get<std::string>("sha256");
                    if (sha256 == std::nullopt || sha256->empty()) {
                        auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                "Field 'sha256' is missing or empty");
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    parser::json::Json json;

                    TRY_BEGIN()
                    focades::analysis::record::File file;
                    file.filename = sha256.value();
                    analysis.analysis.file_read(file);

                    analysis.analysis.clamav->scan(
                        file.content,
                        [&](focades::analysis::threats::av::clamav::record::DTO
                                *p_dto) {
                            json.add(
                                "clamav",
                                std::move(analysis.analysis.clamav->dto_json(p_dto)));
                        });

                    analysis.analysis.yara->scan(
                        file.content,
                        [&](focades::analysis::threats::yara::record::DTO
                                *p_dto) {
                            json.add("yara",
                                     std::move(analysis.analysis.yara->dto_json(p_dto)));
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

                    const auto connected =
                        server::gateway::responses::Connected().add_field(
                            "threats", json);

                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });
    }
} // namespace engine::bridge::endpoints::analysis