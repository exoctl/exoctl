#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/web/extend/web.hxx>

namespace engine::server::extend
{
    class Server : public interface::ILuaOpenLibrary

        ,
                   public interface::IPlugins<Server>

    {
      public:
        Server() = default;
        ~Server() = default;
        void lua_open_library(engine::lua::StateView &) override;

        void _plugins() override;

      private:
        void bind_http_methods(engine::lua::StateView &);
        void bind_response(engine::lua::StateView &);
        void bind_requests(engine::lua::StateView &);
        void bind_server(engine::lua::StateView &);
        void bind_mustache(engine::lua::StateView &);
        void bind_rendered(engine::lua::StateView &);
        void bind_wvalue(sol::state_view &);
    };
} // namespace engine::server::extend
