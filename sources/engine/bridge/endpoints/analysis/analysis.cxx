#include <engine/bridge/endpoints/analysis/analysis.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/filesystem/filesystem.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/logging/logging.hxx>
#include <engine/parser/json/json.hxx>
#include <engine/security/av/clamav/exception.hxx>
#include <engine/security/yara/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <fmt/format.h>
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
        Analysis::rescan();
        Analysis::records();
        Analysis::scan_threats();
        Analysis::update(); // Nova rota para update
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

    void Analysis::rescan()
    {
        m_map.add_route("/rescan", [&]() {
            m_web_scan = std::make_unique<server::gateway::web::Web>();
            m_web_scan->setup(
                &*m_server,
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
                    if (sha256 == std::nullopt) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                fmt::format("Field 'sha256' not found",
                                            min_binary_size));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    focades::analysis::record::Analysis new_anal;
                    focades::analysis::record::Analysis anal;

                    TRY_BEGIN()
                    anal = analysis.analysis_table_get_by_sha256(sha256.value());
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
                    analysis.file_read(file);

                    new_anal = analysis.scan(file);
                    new_anal.id = anal.id;
                    new_anal.file_name = anal.file_name;

                    if (analysis.analysis_table_exists_by_sha256(new_anal)) {
                        analysis.analysis_table_update(new_anal);
                    } else {
                        analysis.analysis_table_insert(new_anal);
                    }
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
                        const auto method_not_allowed =
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
                        if (analysis.analysis_table_exists_by_sha256(anal)) {
                            analysis.analysis_table_update(anal);
                        } else {
                            analysis.analysis_table_insert(anal);
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
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    auto analyses = analysis.analysis_table_get_all();
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
                        record.add("family_id", anal.family_id);
                        record.add("description", anal.description);
                        record.add("owner", anal.owner);
                        record.add("tlsh", anal.tlsh);

                        parser::json::Json family_json;
                        if (anal.family_id != 0) {
                            auto family =
                                analysis.family_table_get_by_id(anal.family_id);
                            if (family.id != 0) {
                                family_json.add("id", family.id);
                                family_json.add("name", family.name);
                                family_json.add("description",
                                                family.description);
                            }
                        }
                        record.add("family", family_json);

                        parser::json::Json tags_json;
                        auto tags =
                            analysis.analysis_tag_get_tags_by_analysis_id(
                                anal.id);
                        for (const auto &tag : tags) {
                            parser::json::Json tag_json;
                            tag_json.add("id", tag.id);
                            tag_json.add("name", tag.name);
                            tag_json.add("description", tag.description);
                            tags_json.add(tag_json);
                        }
                        record.add("tags", tags_json);

                        json.add(record);
                    }

                    const auto connected =
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

                    analysis.clamav->scan(
                        file.content,
                        [&](focades::analysis::threats::av::clamav::record::DTO
                                *p_dto) {
                            json.add(
                                "clamav",
                                std::move(analysis.clamav->dto_json(p_dto)));
                        });

                    analysis.yara->scan(
                        file.content,
                        [&](focades::analysis::threats::yara::record::DTO
                                *p_dto) {
                            json.add("yara",
                                     std::move(analysis.yara->dto_json(p_dto)));
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

    void Analysis::update()
    {
        m_map.add_route("/update", [&]() {
            m_web_update = std::make_unique<server::gateway::web::Web>();
            m_web_update->setup(
                &*m_server,
                BASE_ANALYSIS "/update",
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
                    if (!req.body.empty()) {
                        body.from_string(req.body);
                    } else {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message", "Empty request body");
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    const auto sha256 = body.get<std::string>("sha256");
                    if (!sha256.has_value() || sha256->empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                "Field 'sha256' is missing or empty");
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    focades::analysis::record::Analysis anal;
                    TRY_BEGIN()
                    anal = analysis.analysis_table_get_by_sha256(*sha256);
                    if (anal.sha256.empty()) {
                        const auto not_found =
                            server::gateway::responses::NotFound().add_field(
                                "message",
                                fmt::format("Record with sha256 '{}' not found",
                                            *sha256));
                        return crow::response{not_found.code(),
                                              "application/json",
                                              not_found.tojson().tostring()};
                    }

                    // update fields optionals
                    if (auto description =
                            body.get<std::string>("description")) {
                        if (!description->empty()) {
                            anal.description = *description;
                        }
                    }

                    if (auto file_name = body.get<std::string>("file_name")) {
                        if (!file_name->empty()) {
                            anal.file_name = *file_name;
                        }
                    }

                    // update family
                    if (auto family_obj =
                            body.get<parser::json::Json>("family")) {
                        if (auto family_name =
                                family_obj->get<std::string>("name")) {
                            if (!family_name->empty()) {
                                focades::analysis::record::Family family;
                                family = analysis.family_table_get_by_name(
                                    *family_name);

                                if (family.id == 0) {
                                    family.name = *family_name;
                                    family.description =
                                        family_obj
                                            ->get<std::string>("description")
                                            .value_or("");
                                    analysis.family_table_insert(family);
                                    family = analysis.family_table_get_by_name(
                                        *family_name);
                                }
                                anal.family_id = family.id;
                            } else {
                                m_server->log->warn("Skipping family with "
                                                    "missing or empty 'name'");
                            }
                        }
                    }

                    // update tags
                    if (auto tags_array =
                            body.get<std::vector<parser::json::Json>>("tags")) {
                        for (const auto &tag_json : *tags_array) {
                            if (!tag_json.document.IsObject()) {
                                m_server->log->warn("Skipping tag: expected an "
                                                    "object, got a non-object");
                                continue;
                            }

                            auto tag_name = tag_json.get<std::string>("name");
                            if (!tag_name.has_value() || tag_name->empty()) {
                                m_server->log->warn("Skipping tag with missing "
                                                    "or empty 'name' field");
                                continue;
                            }

                            focades::analysis::record::Tag tag;
                            tag = analysis.tag_table_get_by_name(*tag_name);
                            if (tag.id == 0) {
                                tag.name = *tag_name;
                                tag.description =
                                    tag_json.get<std::string>("description")
                                        .value_or("");
                                analysis.tag_table_insert(tag);
                                tag = analysis.tag_table_get_by_name(*tag_name);
                            }

                            auto existing_tags =
                                analysis.analysis_tag_get_tags_by_analysis_id(
                                    anal.id);
                            if (std::none_of(existing_tags.begin(),
                                             existing_tags.end(),
                                             [&tag](const auto &t) {
                                                 return t.id == tag.id;
                                             })) {
                                focades::analysis::record::AnalysisTag
                                    analysis_tag;
                                analysis_tag.analysis_id = anal.id;
                                analysis_tag.tag_id = tag.id;
                                analysis.analysis_tag_table_insert(
                                    analysis_tag);
                            }
                        }
                    }

                    analysis.analysis_table_update(anal);
                    TRY_END()
                    CATCH(focades::analysis::exception::Scan,
                          return crow::response{
                              server::gateway::responses::InternalServerError()
                                  .code()};)

                    const auto accept =
                        server::gateway::responses::Accepted().add_field(
                            "sha256", anal.sha256);

                    return crow::response{accept.code(),
                                          "application/json",
                                          accept.tojson().tostring()};
                });
        });
    }

} // namespace engine::bridge::endpoints::analysis