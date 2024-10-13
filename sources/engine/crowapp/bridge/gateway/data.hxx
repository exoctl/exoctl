#pragma once

#include <engine/crowapp/bridge/gateway/map/map.hxx>
#include <engine/crowapp/bridge/gateway/websocket/websocket.hxx>
#include <engine/crowapp/crowapp.hxx>
#include <engine/crowapp/focades/data/metadata/metadata.hxx>
#include <engine/interfaces/igateway.hxx>
#include <memory>

#define BASE_DATA API_PREFIX "/data"

namespace engine
{
    namespace crowapp
    {
        namespace bridge
        {
            class Data : public interface::IGateway
            {
              public:
                Data(CrowApp &);
                ~Data();

                void load() const override;

              private:
                CrowApp &m_crowapp;
                mutable gateway::Map m_map;

                std::unique_ptr<gateway::WebSocket> m_socket_metadata;
                std::unique_ptr<focades::data::Metadata> m_data_metadata;

                void prepare();
                void data_metadata();
            };
        } // namespace bridge
    } // namespace crowapp
} // namespace engine