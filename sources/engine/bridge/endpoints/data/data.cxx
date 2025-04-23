#include <engine/bridge/endpoints/data/data.hxx>

namespace engine::bridge::endpoints
{
    Data::Data()
        : m_map(BASE_DATA),
          m_data_metadata(std::make_shared<focades::data::metadata::Metadata>())
    {
    }

    void Data::setup(server::Server &p_server)
    {
        m_server = &p_server;

        if (!p_server.config->get("bridge.endpoint.data.enable")
                 .value<bool>()
                 .value()) {
            m_server->log->warn("Gateway data not enabled");
            return;
        }

        // add new routes
        Data::data_metadata();
    }
#ifdef ENGINE_PRO
    void Data::_plugins()
    {
        focades::data::metadata::Metadata::plugins();
        plugins::Plugins::lua.state.new_usertype<endpoints::Data>(
            "Data", "metadata", &endpoints::Data::m_data_metadata);
    }
#endif

    void Data::data_metadata()
    {
        m_map.add_route("/metadata", [&]() {
            m_web_metadata = std::make_unique<engine::server::gateway::Web>();
            m_web_metadata->setup(
                *m_server,
                BASE_DATA "/metadata",
                [&](const crow::request &req) -> crow::response {
                    if (req.body.size() > 0) {
                        std::string data;
                        m_data_metadata->parse(
                            req.body,
                            [&](focades::data::metadata::record::DTO *p_dto) {
                                data.assign(m_data_metadata->dto_json(p_dto)
                                                .to_string());
                            });
                        return crow::response(200, "application/json", data);
                    }

                    return crow::response(crow::status::BAD_REQUEST);
                },
                {crow::HTTPMethod::POST});
        });
    }

    void Data::load() const
    {
        if (m_server->config->get("bridge.endpoint.data.enable")
                .value<bool>()
                .value()) {
            m_map.get_routes(
                [&](const std::string p_route) { m_map.call_route(p_route); });
        }
    }
} // namespace engine::bridge::endpoints