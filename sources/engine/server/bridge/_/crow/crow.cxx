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
        plugins::Plugins::lua.state.new_usertype<crow::response>(
            "response",
            sol::constructors<crow::response(int code_, std::string body_)>());

        plugins::Plugins::lua.state.new_usertype<crow::request>(
            "requests",
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
