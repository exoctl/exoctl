#include "responses.hxx"
#include <engine/server/gateway/responses/responses.hxx>
#include <engine/server/server.hxx>

namespace engine::server::gateway::responses
{
    const int MethodNotAllowed::_code() const
    {
        return 405;
    }

    const std::string MethodNotAllowed::_status() const
    {
        return "method_not_allowed";
    }

    const std::string MethodNotAllowed::_message() const
    {
        return "Method not implemented";
    }

    const int InternalServerError::_code() const
    {
        return 500;
    }

    const std::string InternalServerError::_status() const
    {
        return "internal_server_error";
    }

    const std::string InternalServerError::_message() const
    {
        return "Internal Server Error";
    }

    const int TooManyRequests::_code() const
    {
        return 429;
    }

    const std::string TooManyRequests::_status() const
    {
        return "too_many_requests";
    }

    const std::string TooManyRequests::_message() const
    {
        return "Too Many Requests";
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

    const int Accepted::_code() const
    {
        return 202;
    }

    const std::string Accepted::_status() const
    {
        return "accepted";
    }

    const std::string Accepted::_message() const
    {
        return "Accepted successfully";
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

    const int BadRequests::_code() const
    {
        return 400;
    }

    const std::string BadRequests::_status() const
    {
        return "bad_requests";
    }

    const std::string BadRequests::_message() const
    {
        return "Bad requests raw data";
    }

} // namespace engine::server::gateway::responses