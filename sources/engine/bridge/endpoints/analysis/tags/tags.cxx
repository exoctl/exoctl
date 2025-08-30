#include <engine/bridge/endpoints/analysis/tags/tags.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <fmt/format.h>

namespace engine::bridge::endpoints::analysis
{
    void Tags::setup(Analysis &analysis)
    {
        analysis.map_.add_route("/tags", [&]() {
            analysis.web_tags_ = std::make_unique<server::gateway::web::Web>();
            analysis.web_tags_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/tags",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::GET) {
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    auto tags = analysis.analysis.database->tag_table_get_all();
                    parser::json::Json json;
                    for (const auto &tag : tags) {
                        parser::json::Json tag_json;
                        tag_json.add("id", tag.id);
                        tag_json.add("name", tag.name);
                        tag_json.add("description", tag.description);
                        json.add(tag_json);
                    }

                    const auto connected =
                        server::gateway::responses::Connected().add_field(
                            "tags", json);
                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/tags/create", [&]() {
            analysis.web_create_tag_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_create_tag_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/tags/create",
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

                    const auto &name = body.get<std::string>("name");
                    if (name == std::nullopt || name->empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                fmt::format(
                                    "Field 'name' is missing or empty '{}'",
                                    body.tostring()));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    const auto conflict =
                        server::gateway::responses::Conflict().add_field(
                            "message",
                            fmt::format("Tag with name '{}' already exists",
                                        name.value()));

                    focades::analysis::database::record::Tag tag;
                    TRY_BEGIN()

                    tag.name = name.value();
                    tag.description =
                        body.get<std::string>("description").value_or("");
                    analysis.analysis.save_tags(tag);

                    TRY_END()
                    CATCH(engine::focades::analysis::exception::TagExists,
                          return crow::response(conflict.code(),
                                                "application/json",
                                                conflict.tojson().tostring()));

                    parser::json::Json tag_json;
                    tag_json.add("id", tag.id);
                    tag_json.add("name", tag.name);
                    tag_json.add("description", tag.description);

                    const auto created =
                        server::gateway::responses::Created().add_field(
                            "tag", tag_json);
                    return crow::response{created.code(),
                                          "application/json",
                                          created.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/tags/update", [&]() {
            analysis.web_update_tag_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_update_tag_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/tags/update",
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

                    const auto &id = body.get<uint16_t>("id");
                    if (id == std::nullopt) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message",
                                fmt::format(
                                    "Field 'id' is missing or empty '{}'",
                                    body.tostring()));
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    focades::analysis::database::record::Tag tag;

                    const auto not_found =
                        server::gateway::responses::NotFound().add_field(
                            "message",
                            fmt::format("Tag with name '{}' not found",
                                        id.value()));

                    TRY_BEGIN()
                    tag.id = id.value();
                    tag.name = body.get<std::string>("name").value_or(tag.name);
                    tag.description = body.get<std::string>("description")
                                          .value_or(tag.description);

                    analysis.analysis.update_tags(tag);

                    TRY_END()
                    CATCH(engine::focades::analysis::exception::TagNotFound,
                          return crow::response(not_found.code(),
                                                "application/json",
                                                not_found.tojson().tostring()));

                    parser::json::Json tag_json;
                    tag_json.add("name", tag.name);
                    tag_json.add("description", tag.description);
                    tag_json.add("id", tag.id);

                    const auto accepted =
                        server::gateway::responses::Accepted().add_field(
                            "tag", tag_json);

                    return crow::response{accepted.code(),
                                          "application/json",
                                          accepted.tojson().tostring()};
                });
        });
    }
} // namespace engine::bridge::endpoints::analysis