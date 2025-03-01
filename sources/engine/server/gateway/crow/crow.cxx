#ifdef ENGINE_PRO

#include <engine/server/gateway/crow/crow.hxx>
#include <engine/server/server.hxx>

namespace engine::server::gateway
{
    void Crow::_plugins()
    {
        plugins::Plugins::lua.state.new_enum<crow::HTTPMethod>(
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

        plugins::Plugins::lua.state.new_usertype<crow::response>(
            "Response",
            sol::constructors<crow::response(int, std::string),
                              crow::response(std::string),
                              crow::response(std::string, std::string),
                              crow::response(int, std::string, std::string),
                              crow::response(int)>(),
            "set_header",
            &crow::response::set_header,
            "add_header",
            &crow::response::add_header);

        plugins::Plugins::lua.state.new_usertype<crow::request>(
            "Requests",
            "method",
            sol::readonly(&crow::request::method),
            "raw_url",
            sol::readonly(&crow::request::raw_url),
            "url",
            sol::readonly(&crow::request::url),
            //"url_params",
            // sol::readonly(&crow::request::url_params),
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

} // namespace engine::server::gateway

#endif
