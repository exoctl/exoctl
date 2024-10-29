#include <engine/server/bridge/gateway/websocket/responses/responses.hxx>

namespace engine::server::bridge::gateway::websocket::responses
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
        return crow::websocket::CloseStatusCode::UnacceptableData;
    }

    const std::string UnsupportedData::_status() const
    {
        return "unsupported_data";
    }

    const std::string UnsupportedData::_message() const
    {
        return "Message received not supported by the server.";
    }

    const parser::Json InvalidTokenJWT::_to_json() const
    {
        parser::Json json;

        json.add_member_string("status", InvalidTokenJWT::_status());
        json.add_member_string("message", InvalidTokenJWT::_message());
        json.add_member_int("code", InvalidTokenJWT::_code());

        return json;
    }

    const int InvalidTokenJWT::_code() const
    {
        return 403;
    }

    const std::string InvalidTokenJWT::_status() const
    {
        return "invalid_token_jwt";
    }

    const std::string InvalidTokenJWT::_message() const
    {
        return "Token is not valid";
    }

} // namespace engine::server::bridge::gateway::websocket::responses