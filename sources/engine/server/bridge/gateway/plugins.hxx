#ifdef ENGINE_PRO

#pragma once

#include <engine/interfaces/igateway.hxx>
#include <engine/server/bridge/gateway/map/map.hxx>
#include <engine/server/bridge/gateway/web/web.hxx>
#include <engine/server/server.hxx>
#include <memory>

#define BASE_PLUGINS API_PREFIX "/plugins"

namespace engine::server::bridge
{
    class Plugins : public interface::IGateway
    {
      public:
        Plugins(Server &);
        ~Plugins() = default;

        void load() const override;

      private:
        Server &m_server;
        mutable gateway::Map m_map;

        std::unique_ptr<gateway::Web> m_web_plugins;

        void prepare();
        void plugins();
    };
} // namespace engine::server::bridge

#endif