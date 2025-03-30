#pragma once

#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/server/gateway/web/extend/web.hxx>

namespace engine::server::extend
{
    class Server : public interface::IBind
#ifdef ENGINE_PRO
        ,
                   public interface::ISubPlugins<Server>
#endif
    {
      public:
        Server() = default;
        ~Server() = default;
        void bind_to_lua(sol::state_view &) override;

#ifdef ENGINE_PRO
        void _plugins() override;
#endif

      private:
        void bind_http_methods(sol::state_view &);
        void bind_response(sol::state_view &);
        void bind_requests(sol::state_view &);
        void bind_server(sol::state_view &);
        void bind_mustache(sol::state_view &);
        void bind_rendered(sol::state_view &);
        void bind_wvalue(sol::state_view&);
    };
} // namespace engine::server::extend
