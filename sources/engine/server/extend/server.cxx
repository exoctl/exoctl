#include <engine/plugins/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <engine/server/extend/server.hxx>
#include <engine/server/server.hxx>

namespace engine::server::extend
{
    void Server::bind_http_methods(sol::state_view &p_lua)
    {
        p_lua.new_enum<crow::HTTPMethod>(
            "HTTPMethod",
            {{"Delete", crow::HTTPMethod::Delete},
             {"Get", crow::HTTPMethod::Get},
             {"Head", crow::HTTPMethod::Head},
             {"Post", crow::HTTPMethod::Post},
             {"Put", crow::HTTPMethod::Put},
             {"Connect", crow::HTTPMethod::Connect},
             {"Options", crow::HTTPMethod::Options},
             {"Trace", crow::HTTPMethod::Trace},
             {"Patch", crow::HTTPMethod::Patch},
             {"Purge", crow::HTTPMethod::Purge},
             {"Copy", crow::HTTPMethod::Copy},
             {"Lock", crow::HTTPMethod::Lock},
             {"MkCol", crow::HTTPMethod::MkCol},
             {"Move", crow::HTTPMethod::Move},
             {"Propfind", crow::HTTPMethod::Propfind},
             {"Proppatch", crow::HTTPMethod::Proppatch},
             {"Search", crow::HTTPMethod::Search},
             {"Unlock", crow::HTTPMethod::Unlock},
             {"Bind", crow::HTTPMethod::Bind},
             {"Rebind", crow::HTTPMethod::Rebind},
             {"Unbind", crow::HTTPMethod::Unbind},
             {"Acl", crow::HTTPMethod::Acl},
             {"Report", crow::HTTPMethod::Report},
             {"MkActivity", crow::HTTPMethod::MkActivity},
             {"Checkout", crow::HTTPMethod::Checkout},
             {"Merge", crow::HTTPMethod::Merge},
             {"MSearch", crow::HTTPMethod::MSearch},
             {"Notify", crow::HTTPMethod::Notify},
             {"Subscribe", crow::HTTPMethod::Subscribe},
             {"Unsubscribe", crow::HTTPMethod::Unsubscribe},
             {"MkCalendar", crow::HTTPMethod::MkCalendar},
             {"Link", crow::HTTPMethod::Link},
             {"Unlink", crow::HTTPMethod::Unlink},
             {"Source", crow::HTTPMethod::Source},
             {"InternalMethodCount", crow::HTTPMethod::InternalMethodCount}});
    }

    void Server::bind_response(sol::state_view &p_lua)
    {
        p_lua.new_usertype<crow::response>(
            "Response",
            sol::constructors<crow::response(int, std::string),
                              crow::response(std::string),
                              crow::response(std::string, std::string),
                              crow::response(int, std::string, std::string),
                              crow::response(int)>(),
            "set_header",
            &crow::response::set_header,
            "add_header",
            &crow::response::add_header,
            "get_header_value",
            &crow::response::get_header_value,
            "redirect",
            &crow::response::redirect);
    }

    void Server::bind_requests(sol::state_view &p_lua)
    {
        p_lua.new_usertype<crow::request>(
            "Requests",
            "method",
            sol::readonly(&crow::request::method),
            "raw_url",
            sol::readonly(&crow::request::raw_url),
            "url",
            sol::readonly(&crow::request::url),
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

    void Server::bind_server(sol::state_view &p_lua)
    {
        p_lua.new_usertype<server::Server>(
            "Server",
            sol::constructors<server::Server()>(),
            "setup",
            &server::Server::setup,
            "run_async",
            &server::Server::run_async,
            "load",
            &server::Server::load,            
            "stop",
            &server::Server::stop,
            "tick",
            sol::overload([](server::Server &self,
                             int32_t milliseconds,
                             sol::function callback) {
                self.tick(std::chrono::milliseconds(milliseconds), callback);
            }),
            "port",
            sol::readonly(&server::Server::port),
            "bindaddr",
            sol::readonly(&server::Server::bindaddr),
            "concurrency",
            sol::readonly(&server::Server::concurrency),
            "ssl_enable",
            sol::readonly(&server::Server::ssl_enable),
            "certfile",
            sol::readonly(&server::Server::certfile),
            "keyfile",
            sol::readonly(&server::Server::keyfile));
    }

#ifdef ENGINE_PRO
    void Server::_plugins()
    {
        Server::bind_http_methods(plugins::Plugins::lua.state);
        Server::bind_response(plugins::Plugins::lua.state);
        Server::bind_requests(plugins::Plugins::lua.state);
        Server::bind_server(plugins::Plugins::lua.state);

        gateway::web::extend::Web::plugins();
    }
#endif

    void Server::bind_to_lua(sol::state_view &p_lua)
    {
        Server::bind_server(p_lua);
    }
} // namespace engine::server::extend
