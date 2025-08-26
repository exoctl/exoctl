#include <engine/server/gateway/web/web.hxx>

namespace engine::server::gateway::web
{
    void Web::setup(Server *p_server,
                    const std::string &p_url,
                    on_request_callback on_request)
    {
        server_ = &*p_server;

        server_->log->info("Creating HTTP route for URL: '{}'", p_url);

        route_ = &server_->route_dynamic(p_url);
        Web::active_all_methods();
        (*route_)(on_request);
        route_->validate();
    }

    void Web::active_all_methods()
    {
        // accept all methods
        route_->methods(crow::HTTPMethod::Delete,
                         crow::HTTPMethod::Get,
                         crow::HTTPMethod::Head,
                         crow::HTTPMethod::Post,
                         crow::HTTPMethod::Put,
                         crow::HTTPMethod::Connect,
                         crow::HTTPMethod::Options,
                         crow::HTTPMethod::Trace,
                         crow::HTTPMethod::Patch,
                         crow::HTTPMethod::Purge,
                         crow::HTTPMethod::Copy,
                         crow::HTTPMethod::Lock,
                         crow::HTTPMethod::MkCol,
                         crow::HTTPMethod::Move,
                         crow::HTTPMethod::Propfind,
                         crow::HTTPMethod::Proppatch,
                         crow::HTTPMethod::Search,
                         crow::HTTPMethod::Unlock,
                         crow::HTTPMethod::Bind,
                         crow::HTTPMethod::Rebind,
                         crow::HTTPMethod::Unbind,
                         crow::HTTPMethod::Acl,
                         crow::HTTPMethod::Report,
                         crow::HTTPMethod::MkActivity,
                         crow::HTTPMethod::Checkout,
                         crow::HTTPMethod::Merge,
                         crow::HTTPMethod::MSearch,
                         crow::HTTPMethod::Notify,
                         crow::HTTPMethod::Subscribe,
                         crow::HTTPMethod::Unsubscribe,
                         crow::HTTPMethod::MkCalendar,
                         crow::HTTPMethod::Link,
                         crow::HTTPMethod::Unlink,
                         crow::HTTPMethod::Source);
    }
} // namespace engine::server::gateway::web
