#include <engine/server/bridge/gateway/data.hxx>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            Data::Data(Server &p_server)
                : m_server(p_server), m_map(BASE_DATA)
            {
                Data::prepare();

                // add new routes
                Data::data_metadata();
            }

            Data::~Data()
            {
            }

            void Data::data_metadata()
            {
                m_map.add_route("/metadata", [&]() {
                    m_socket_metadata = std::make_unique<gateway::WebSocket>(
                        m_server,
                        BASE_DATA "/metadata",
                        UINT64_MAX,
                        [&](gateway::websocket::Context &p_context,
                            crow::websocket::connection &p_conn,
                            const std::string &p_data,
                            bool p_is_binary) {
                            m_data_metadata->parse(
                                p_data,
                                [&](focades::data::metadata::record::DTO
                                        *p_dto) {
                                    p_context.broadcast_text(
                                        &p_conn,
                                        m_data_metadata->dto_json(p_dto)
                                            .to_string());
                                });
                        });
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