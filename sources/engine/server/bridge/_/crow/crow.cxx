#ifdef ENGINE_PRO

#include <engine/server/bridge/_/crow/crow.hxx>
#include <engine/server/server.hxx>

namespace engine::server::bridge::_
{
    void Crow::register_plugins()
    {
        /*nothing*/
    }

    void Crow::plugins()
    {
        plugins::Plugins::lua.state.new_usertype<crow::HTTPMethod>(
            "HTTPMethod",
            sol::constructors<crow::HTTPMethod()>(),
            "Delete",
            sol::var(crow::HTTPMethod::Delete),
            "Get",
            sol::var(crow::HTTPMethod::Get),
            "Head",
            sol::var(crow::HTTPMethod::Head),
            "Post",
            sol::var(crow::HTTPMethod::Post),
            "Put",
            sol::var(crow::HTTPMethod::Put),
            "Connect",
            sol::var(crow::HTTPMethod::Connect),
            "Options",
            sol::var(crow::HTTPMethod::Options),
            "Trace",
            sol::var(crow::HTTPMethod::Trace),
            "Patch",
            sol::var(crow::HTTPMethod::Patch),
            "Purge",
            sol::var(crow::HTTPMethod::Purge),
            "Copy",
            sol::var(crow::HTTPMethod::Copy),
            "Lock",
            sol::var(crow::HTTPMethod::Lock),
            "MkCol",
            sol::var(crow::HTTPMethod::MkCol),
            "Move",
            sol::var(crow::HTTPMethod::Move),
            "Propfind",
            sol::var(crow::HTTPMethod::Propfind),
            "Proppatch",
            sol::var(crow::HTTPMethod::Proppatch),
            "Search",
            sol::var(crow::HTTPMethod::Search),
            "Unlock",
            sol::var(crow::HTTPMethod::Unlock),
            "Bind",
            sol::var(crow::HTTPMethod::Bind),
            "Rebind",
            sol::var(crow::HTTPMethod::Rebind),
            "Unbind",
            sol::var(crow::HTTPMethod::Unbind),
            "Acl",
            sol::var(crow::HTTPMethod::Acl),
            "Report",
            sol::var(crow::HTTPMethod::Report),
            "MkActivity",
            sol::var(crow::HTTPMethod::MkActivity),
            "Checkout",
            sol::var(crow::HTTPMethod::Checkout),
            "Merge",
            sol::var(crow::HTTPMethod::Merge),
            "MSearch",
            sol::var(crow::HTTPMethod::MSearch),
            "Notify",
            sol::var(crow::HTTPMethod::Notify),
            "Subscribe",
            sol::var(crow::HTTPMethod::Subscribe),
            "Unsubscribe",
            sol::var(crow::HTTPMethod::Unsubscribe),
            "MkCalendar",
            sol::var(crow::HTTPMethod::MkCalendar),
            "Link",
            sol::var(crow::HTTPMethod::Link),
            "Unlink",
            sol::var(crow::HTTPMethod::Unlink),
            "Source",
            sol::var(crow::HTTPMethod::Source),
            "InternalMethodCount",
            sol::var(crow::HTTPMethod::InternalMethodCount));

        plugins::Plugins::lua.state.new_usertype<crow::response>(
            "Response",
            sol::constructors<crow::response(int, std::string),
                              crow::response(std::string),
                              crow::response(std::string, std::string),
                              crow::response(int, std::string, std::string),
                              crow::response(int)>());

        plugins::Plugins::lua.state.new_usertype<crow::request>(
            "Requests",
            "method",
            sol::readonly(&crow::request::method),
            "raw_url",
            sol::readonly(&crow::request::raw_url),
            "url",
            sol::readonly(&crow::request::url),
            "url_params",
            sol::readonly(&crow::request::url_params),
            "body",
            sol::readonly(&crow::request::body),
            "remote_ip_address",
            sol::readonly(&crow::request::remote_ip_address),
            "http_ver_major",
            sol::readonly(&crow::request::http_ver_major),
            "http_ver_minor",
            sol::readonly(&crow::request::http_ver_minor),
            "keep_alive",
            sol::readonly(&crow::request::keep_alive),
            "close_connection",
            sol::readonly(&crow::request::close_connection),
            "upgrade",
            sol::readonly(&crow::request::upgrade));
    }

} // namespace engine::server::bridge::_

#endif
