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
        server::Server &server_;
        mutable map::Map map_;

        std::unique_ptr<engine::server::gateway::web::Web> web_plugins_;

        void prepare();
        void plugins();
    };
} // namespace engine::bridge::endpoints