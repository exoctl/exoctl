#pragma once

#include <engine/bridge/focades/data/metadata/metadata.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/map/map.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_DATA API_PREFIX "/data"

namespace engine::bridge::endpoints
{
    class Data : public interface::IEndpoint
#ifdef ENGINE_PRO
        ,
                 public interface::IPlugins
#endif
    {
      public:
        Data(server::Server &);
        ~Data() = default;
#ifdef ENGINE_PRO
        void register_plugins() override;
#endif
        void load() const override;

      private:
        server::Server &m_server;
        mutable engine::server::gateway::Map m_map;

        std::unique_ptr<engine::server::gateway::Web> m_web_metadata;
        std::unique_ptr<focades::data::metadata::Metadata> m_data_metadata;

        void prepare();
        void data_metadata();
    };
} // namespace engine::bridge::endpoints
