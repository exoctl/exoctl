#include <engine/crowapp/bridge/gateway/websocket/responses.hxx>

namespace engine::crowapp::bridge::gateway::websocket::responses
{
    Connected::Connected()
    {
    }
    
    const parser::Json Connected::_to_json() const
    {
        parser::Json json;

        json.add_member_string("status", Connected::_status());
        json.add_member_string("message", Connected::_message());
        json.add_member_int("code", Connected::_code());

        return json;
    }

    const int Connected::_code() const
    {
        return 200;
    }

    const std::string Connected::_status() const
    {
        return "connected";
    }

    const std::string Connected::_message() const
    {
        return "Connected successfully";
    }

    UnsupportedData::UnsupportedData()
    {
    }

    const parser::Json UnsupportedData::_to_json() const
    {
        parser::Json json;

        json.add_member_string("status", UnsupportedData::_status());
        json.add_member_string("message", UnsupportedData::_message());
        json.add_member_int("code", UnsupportedData::_code());

        return json;
    }

    const int UnsupportedData::_code() const
    {
        return 1003;
    }

    const std::string UnsupportedData::_status() const
    {
        return "unsupported";
    }

    const std::string UnsupportedData::_message() const
    {
        return "Message received not supported by the server.";
    }

} // namespace engine::crowapp::bridge::gateway::websocket::responses