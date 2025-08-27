#include <engine/bridge/endpoints/analysis/records/records.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <fmt/format.h>

namespace engine::bridge::endpoints::analysis
{
    void Records::setup(Analysis &analysis)
    {
        analysis.map_.add_route("/records", [&]() {
            analysis.web_records_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_records_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/records",
                [&](const crow::request &req) -> const crow::response {
                    auto serealize_analysis_to_json =
                        [&](focades::analysis::database::record::Analysis &anal)
                        -> parser::json::Json {
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
                                analysis.analysis.database
                                    ->family_table_get_by_id(anal.family_id);
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
                            analysis.analysis.database
                                ->analysis_tag_get_tags_by_analysis_id(anal.id);
                        for (const auto &tag : tags) {
                            parser::json::Json tag_json;
                            tag_json.add("id", tag.id);
                            tag_json.add("name", tag.name);
                            tag_json.add("description", tag.description);
                            tags_json.add(tag_json);
                        }
                        record.add("tags", tags_json);

                        return record;
                    };

                    if (req.method == crow::HTTPMethod::GET) {
                        auto analysis_vec = analysis.analysis.database
                                                ->analysis_table_get_all();
                        parser::json::Json json;
                        for (auto &anal : analysis_vec) {
                            json.add(serealize_analysis_to_json(anal));
                        }
                        const auto connected =
                            server::gateway::responses::Connected().add_field(
                                "records", json);

                        return crow::response{connected.code(),
                                              "application/json",
                                              connected.tojson().tostring()};

                    } else if (req.method == crow::HTTPMethod::POST) {
                        parser::json::Json body;
                        body.from_string(crow::utility::trim(req.body));

                        const auto &sha256 = body.get<std::string>("sha256");
                        if (sha256 == std::nullopt || sha256->empty()) {
                            const auto bad_requests =
                                server::gateway::responses::BadRequests()
                                    .add_field("message",
                                               "Field 'sha256' is missing "
                                               "or empty");
                            return crow::response{
                                bad_requests.code(),
                                "application/json",
                                bad_requests.tojson().tostring()};
                        }

                        focades::analysis::database::record::Analysis anal;
                        parser::json::Json record_anal;

                        anal =
                            analysis.analysis.database
                                ->analysis_table_get_by_sha256(sha256.value());
                        if (anal.sha256.empty()) {
                            const auto not_found =
                                server::gateway::responses::NotFound()
                                    .add_field("message",
                                               fmt::format("Record with sha256 "
                                                           "'{}' not found",
                                                           sha256.value()));
                            return crow::response{
                                not_found.code(),
                                "application/json",
                                not_found.tojson().tostring()};
                        }

                        record_anal = serealize_analysis_to_json(anal);

                        const auto connected =
                            server::gateway::responses::Connected().add_field(
                                "record", record_anal);
                        return crow::response{connected.code(),
                                              "application/json",
                                              connected.tojson().tostring()};
                    }

                    const auto method_not_allowed =
                        server::gateway::responses::MethodNotAllowed();
                    return crow::response{
                        method_not_allowed.code(),
                        "application/json",
                        method_not_allowed.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/records/delete", [&]() {
            analysis.web_records_delete_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_records_delete_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/records/delete",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    } else if (req.body.empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message", std::string("Empty request body"));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    parser::json::Json body;
                    body.from_string(crow::utility::trim(req.body));

                    const auto &sha256 = body.get<std::string>("sha256");
                    if (sha256 == std::nullopt || sha256->empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                std::string("Field 'sha256' is "
                                            "missing or empty"));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    focades::analysis::database::record::Analysis anal =
                        analysis.analysis.database
                            ->analysis_table_get_by_sha256(sha256.value());
                    if (anal.sha256.empty()) {
                        const auto not_found =
                            server::gateway::responses::NotFound().add_field(
                                "message",
                                fmt::format("Record with sha256 "
                                            "'{}' not found",
                                            sha256.value()));
                        return crow::response{not_found.code(),
                                              "application/json",
                                              not_found.tojson().tostring()};
                    }

                    analysis.analysis.database->analysis_table_delete(
                        sha256.value());
                    analysis.analysis.file_remove(
                        focades::analysis::record::File{.filename =
                                                            sha256.value()});

                    const auto accept =
                        server::gateway::responses::Accepted().add_field(
                            "message",
                            fmt::format("Record with sha256 '{}' deleted",
                                        sha256.value()));
                    return crow::response{accept.code(),
                                          "application/json",
                                          accept.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/records/update", [&]() {
            analysis.web_records_update_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_records_update_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/records/update",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::POST) {
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    } else if (req.body.empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message", std::string("Empty request body"));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    parser::json::Json body;
                    body.from_string(crow::utility::trim(req.body));

                    const auto &sha256 = body.get<std::string>("sha256");
                    if (sha256 == std::nullopt || sha256->empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                std::string("Field 'sha256' is "
                                            "missing or empty"));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    focades::analysis::database::record::Analysis anal;

                    anal = analysis.analysis.database
                               ->analysis_table_get_by_sha256(sha256.value());
                    if (anal.sha256.empty()) {
                        const auto not_found =
                            server::gateway::responses::NotFound().add_field(
                                "message",
                                fmt::format("Record with sha256 "
                                            "'{}' not found",
                                            sha256.value()));
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
                                focades::analysis::database::record::Family
                                    family;
                                family = analysis.analysis.database
                                             ->family_table_get_by_name(
                                                 *family_name);

                                if (family.id == 0) {
                                    family.name = *family_name;
                                    family.description =
                                        family_obj
                                            ->get<std::string>("description")
                                            .value_or(family.description);
                                    analysis.analysis.database
                                        ->family_table_insert(family);
                                }
                                anal.family_id = family.id;
                            } else {
                                analysis.server_->log->warn(
                                    "Skipping family with "
                                    "missing or empty 'name'");
                            }
                        }
                    }

                    // update tags
                    if (auto tags_array =
                            body.get<std::vector<parser::json::Json>>("tags")) {
                        auto existing_tags =
                            analysis.analysis.database
                                ->analysis_tag_get_tags_by_analysis_id(anal.id);

                        for (const auto &tag : existing_tags) {
                            analysis.analysis.database
                                ->analysis_tag_table_delete(anal.id, tag.id);
                        }

                        for (const auto &tag_json : *tags_array) {
                            if (!tag_json.document.IsObject()) {
                                analysis.server_->log->warn(
                                    "Skipping tag: expected an object, got a "
                                    "non-object");
                                continue;
                            }

                            auto tag_name = tag_json.get<std::string>("name");
                            if (!tag_name.has_value() || tag_name->empty()) {
                                analysis.server_->log->warn(
                                    "Skipping tag with missing or empty 'name' "
                                    "field");
                                continue;
                            }

                            focades::analysis::database::record::Tag tag;
                            tag = analysis.analysis.database
                                      ->tag_table_get_by_name(tag_name.value());

                            tag.name = tag_name.value();

                            if (auto tag_description =
                                    tag_json.get<std::string>("description")) {
                                if (!tag_description->empty()) {
                                    tag.description = *tag_description;
                                }
                            }

                            if (tag.id == 0) {
                                analysis.analysis.database->tag_table_insert(
                                    tag);
                                tag = analysis.analysis.database
                                          ->tag_table_get_by_name(
                                              tag_name.value()); // get new id
                            } else {
                                analysis.analysis.database->tag_table_update(
                                    tag);
                            }

                            auto existing_tags =
                                analysis.analysis.database
                                    ->analysis_tag_get_tags_by_analysis_id(
                                        anal.id);
                            if (std::none_of(existing_tags.begin(),
                                             existing_tags.end(),
                                             [&tag](const auto &t) {
                                                 return t.id == tag.id;
                                             })) {
                                focades::analysis::database::record::AnalysisTag
                                    analysis_tag;

                                analysis_tag.analysis_id = anal.id;
                                analysis_tag.tag_id = tag.id;
                                analysis.analysis.database
                                    ->analysis_tag_table_insert(analysis_tag);
                            }
                        }
                    }

                    analysis.analysis.database->analysis_table_update(anal);

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