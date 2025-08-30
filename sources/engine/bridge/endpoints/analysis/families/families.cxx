#include <engine/bridge/endpoints/analysis/families/families.hxx>
#include <engine/bridge/exception.hxx>
#include <engine/focades/analysis/exception.hxx>
#include <engine/server/gateway/responses/responses.hxx>
#include <fmt/format.h>

namespace engine::bridge::endpoints::analysis
{
    void Families::setup(Analysis &analysis)
    {
        analysis.map_.add_route("/families", [&]() {
            analysis.web_families_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_families_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/families",
                [&](const crow::request &req) -> const crow::response {
                    if (req.method != crow::HTTPMethod::GET) {
                        const auto method_not_allowed =
                            server::gateway::responses::MethodNotAllowed();
                        return crow::response{
                            method_not_allowed.code(),
                            "application/json",
                            method_not_allowed.tojson().tostring()};
                    }

                    auto families =
                        analysis.analysis.database->family_table_get_all();
                    parser::json::Json json;
                    for (const auto &family : families) {
                        parser::json::Json family_json;
                        family_json.add("id", family.id);
                        family_json.add("name", family.name);
                        family_json.add("description", family.description);
                        json.add(family_json);
                    }

                    const auto connected =
                        server::gateway::responses::Connected().add_field(
                            "families", json);
                    return crow::response{connected.code(),
                                          "application/json",
                                          connected.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/families/create", [&]() {
            analysis.web_create_family_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_create_family_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/families/create",
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
                            fmt::format("Family with name '{}' already exists",
                                        name.value()));

                    focades::analysis::database::record::Family family;
                    TRY_BEGIN()
                    family.name = name.value();
                    family.description =
                        body.get<std::string>("description").value_or("");

                    analysis.analysis.save_families(family);
                    TRY_END()
                    CATCH(engine::focades::analysis::exception::FamilyExists,
                          return crow::response(conflict.code(),
                                                "application/json",
                                                conflict.tojson().tostring()));

                    parser::json::Json family_json;
                    family_json.add("id", family.id);
                    family_json.add("name", family.name);
                    family_json.add("description", family.description);

                    const auto created =
                        server::gateway::responses::Created().add_field(
                            "family", family_json);

                    return crow::response{created.code(),
                                          "application/json",
                                          created.tojson().tostring()};
                });
        });

        analysis.map_.add_route("/families/update", [&]() {
            analysis.web_update_family_ =
                std::make_unique<server::gateway::web::Web>();
            analysis.web_update_family_->setup(
                &*analysis.server_,
                BASE_ANALYSIS "/families/update",
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

                    focades::analysis::database::record::Family family;

                    const auto not_found =
                        server::gateway::responses::NotFound().add_field(
                            "message",
                            fmt::format("Tag with name '{}' not found",
                                        id.value()));

                    TRY_BEGIN()
                    family.id = id.value();
                    family.name = body.get<std::string>("name").value_or(family.name);
                    family.description = body.get<std::string>("description")
                                          .value_or(family.description);

                    analysis.analysis.update_families(family);

                    TRY_END()
                    CATCH(engine::focades::analysis::exception::TagNotFound,
                          return crow::response(not_found.code(),
                                                "application/json",
                                                not_found.tojson().tostring()));

                    parser::json::Json family_json;
                    family_json.add("name", family.name);
                    family_json.add("description", family.description);
                    family_json.add("id", family.id);

                    const auto accepted =
                        server::gateway::responses::Accepted().add_field(
                            "family", family_json);

                    return crow::response{accepted.code(),
                                          "application/json",
                                          accepted.tojson().tostring()};
                });
        });
    }
} // namespace engine::bridge::endpoints::analysis