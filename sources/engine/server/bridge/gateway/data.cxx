#include <engine/server/bridge/gateway/data.hxx>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            Data::Data(Server &p_server) : m_server(p_server), m_map(BASE_DATA)
            {
                Data::prepare();

                // add new routes
                Data::data_metadata();
            }

            void Data::register_plugins()
            {
                m_data_metadata->register_plugins();
            }

            void Data::data_metadata()
            {
                m_map.add_route("/metadata", [&]() {
                    m_web_metadata = std::make_unique<
                        engine::server::bridge::gateway::Web>();
                    m_web_metadata->setup(
                        m_server,
                        BASE_DATA "/metadata",
                        [&](const crow::request &req) -> crow::response {
                            if (req.body.size() > 0) {
                                std::string data;
                                m_data_metadata->parse(
                                    req.body,
                                    [&](focades::data::metadata::record::DTO
                                            *p_dto) {
                                        data.assign(
                                            m_data_metadata->dto_json(p_dto)
                                                .to_string());
                                    });
                                return crow::response(data);
                            }
                            
                            return crow::response(crow::status::BAD_REQUEST);
                        },
                        {crow::HTTPMethod::POST});
                });
            }

            void Data::prepare()
            {
                LOG(m_server.get_log(),
                    info,
                    "Preparing gateway data routes ...");
                m_data_metadata = std::make_unique<focades::data::Metadata>();
            }

            void Data::load() const
            {
                m_map.get_routes([&](const std::string p_route) {
                    m_map.call_route(p_route);
                });
            }
        } // namespace bridge
    } // namespace server
} // namespace engine