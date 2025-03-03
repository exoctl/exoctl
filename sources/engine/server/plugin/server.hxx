#ifdef ENGINE_PRO

#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/web/plugin/web.hxx>

namespace engine::server::plugin
{
    class Server : public interface::IBind,
                   public interface::ISubPlugins<Server>
    {
      public:
        Server() = default;
        ~Server() = default;
        void bind_to_lua(sol::state_view &) override;
        void _plugins() override;

      private:
        void bind_http_methods(sol::state_view &);
        void bind_response(sol::state_view &);
        void bind_requests(sol::state_view &);
        void bind_server(sol::state_view &);
    };
} // namespace engine::server::plugin

#endif