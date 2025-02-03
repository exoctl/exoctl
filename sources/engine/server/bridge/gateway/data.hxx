#pragma once

#include <engine/interfaces/igateway.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/bridge/gateway/map/map.hxx>
#include <engine/server/bridge/gateway/websocket/websocket.hxx>
#include <engine/server/focades/data/metadata/metadata.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_DATA API_PREFIX "/data"

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            class Data : public interface::IGateway
#ifdef ENGINE_PRO
                ,
                         public interface::IPlugins
#endif
            {
              public:
                Data(Server &);
                ~Data() = default;

                void register_plugins() override;
                void load() const override;

              private:
                Server &m_server;
                mutable gateway::Map m_map;

                std::unique_ptr<gateway::WebSocket> m_socket_metadata;
                std::unique_ptr<focades::data::Metadata> m_data_metadata;

                void prepare();
                void data_metadata();
            };
        } // namespace bridge
    } // namespace server
} // namespace engine