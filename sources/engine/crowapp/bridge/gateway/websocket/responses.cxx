#include <engine/crowapp/bridge/gateway/websocket/responses.hxx>

namespace engine::crowapp::bridge::gateway::websocket::responses
{
    Connected::Connected()
    {
    }

    const parser::Json Connected::to_json() const
    {
        parser::Json json;
        
        json.add_member_string("status", Connected::status());
        json.add_member_int("status", Connected::code());

        return json;
    }

    const int Connected::code() const
    {
        return 200;
    }

    const std::string Connected::status() const
    {
        return "ready";
    }

} // namespace engine::crowapp::bridge::gateway::websocket::responses