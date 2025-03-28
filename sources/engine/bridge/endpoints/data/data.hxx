#pragma once

#include <engine/bridge/focades/data/metadata/metadata.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/bridge/map/map.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_DATA API_PREFIX("data")

namespace engine::bridge::endpoints
{
    class Data : public interface::IEndpoint
#ifdef ENGINE_PRO
        ,
                 public interface::ISubPlugins<Data>
#endif
    {
      public:
        Data();
        void setup(server::Server &);
        ~Data() = default;
#ifdef ENGINE_PRO
        void _plugins() override;
#endif
        void load() const override;

      private:
        server::Server *m_server;
        mutable map::Map m_map;

        std::unique_ptr<engine::server::gateway::Web> m_web_metadata;
        std::shared_ptr<focades::data::metadata::Metadata> m_data_metadata;

        void data_metadata();
    };
} // namespace engine::bridge::endpoints
