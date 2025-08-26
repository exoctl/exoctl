#include <engine/bridge/endpoints/analysis/families/families.hxx>
#include <engine/bridge/exception.hxx>
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

                    auto families = analysis.analysis.family_table_get_all();
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

                    const auto &name = body.get<std::string>("name");
                    if (name == std::nullopt || name->empty()) {
                        const auto bad_requests =
                            server::gateway::responses::BadRequests().add_field(
                                "message", "Field 'name' is missing or empty");
                        return crow::response{bad_requests.code(),
                                              "application/json",
                                              bad_requests.tojson().tostring()};
                    }

                    focades::analysis::record::Family family;
                    family = analysis.analysis.family_table_get_by_name(
                        name.value());
                    if (family.id != 0) {
                        const auto conflict =
                            server::gateway::responses::Conflict().add_field(
                                "message",
                                fmt::format(
                                    "Family with name '{}' already exists",
                                    name.value()));
                        return crow::response{conflict.code(),
                                              "application/json",
                                              conflict.tojson().tostring()};
                    }

                    family.name = name.value();
                    family.description =
                        body.get<std::string>("description").value_or("");
                    analysis.analysis.family_table_insert(family);

                    family = analysis.analysis.family_table_get_by_name(
                        name.value());
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
    }
} // namespace engine::bridge::endpoints::analysis