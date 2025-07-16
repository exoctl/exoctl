#pragma once

#include <engine/bridge/map/map.hxx>
#include <engine/interfaces/iendpoint.hxx>
#include <engine/server/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_PLUGINS API_PREFIX("plugins")

namespace engine::bridge::endpoints
{
    class Plugins : public interface::IEndpoint
    {
      public:
        Plugins(server::Server &);
        ~Plugins() = default;

        void load() const override;

      private:
        server::Server &m_server;
        mutable map::Map m_map;

        std::unique_ptr<engine::server::gateway::web::Web> m_web_plugins;

        void prepare();
        void plugins();
    };
} // namespace engine::bridge::endpoints