#pragma once

#include  <engine/interfaces/iendpoints.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/focades/data/metadata/metadata.hxx>
#include <engine/server/gateway/map/map.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_DATA API_PREFIX "/data"

namespace engine::server::bridge::endpoints
{
    class Data : public interface::IEndpoints
#ifdef ENGINE_PRO
        ,
                 public interface::IPlugins
#endif
    {
      public:
        Data(Server &);
        ~Data() = default;
#ifdef ENGINE_PRO
        void register_plugins() override;
#endif
        void load() const override;

      private:
        Server &m_server;
        mutable engine::server::gateway::Map m_map;

        std::unique_ptr<engine::server::gateway::Web> m_web_metadata;
        std::unique_ptr<focades::data::Metadata> m_data_metadata;

        void prepare();
        void data_metadata();
    };
} // namespace engine::server::bridge::endpoints
