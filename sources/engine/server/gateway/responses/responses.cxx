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

    const int NotFound::_code() const
    {
        return 404;
    }

    const std::string NotFound::_status() const
    {
        return "not_found";
    }

    const int Conflict::_code() const
    {
        return 409;
    }

    const std::string Conflict::_status() const
    {
        return "conflict";
    }

    const int Created::_code() const
    {
        return 201;
    }

    const std::string Created::_status() const
    {
        return "created";
    }

    const int ServiceUnavailable::_code() const
    {
        return 503;
    }

    const std::string ServiceUnavailable::_status() const
    {
        return "service_unavailable";
    }

    const int InternalServerError::_code() const
    {
        return 500;
    }

    const std::string InternalServerError::_status() const
    {
        return "internal_server_error";
    }

    const int TooManyRequests::_code() const
    {
        return 429;
    }

    const std::string TooManyRequests::_status() const
    {
        return "too_many_requests";
    }

    const int Connected::_code() const
    {
        return 200;
    }

    const std::string Connected::_status() const
    {
        return "connected";
    }

    const int Accepted::_code() const
    {
        return 202;
    }

    const std::string Accepted::_status() const
    {
        return "accepted";
    }

    const int UnsupportedData::_code() const
    {
        return crow::websocket::CloseStatusCode::UnacceptableData;
    }

    const std::string UnsupportedData::_status() const
    {
        return "unsupported_data";
    }

    const int InvalidTokenJWT::_code() const
    {
        return 403;
    }

    const std::string InvalidTokenJWT::_status() const
    {
        return "invalid_token_jwt";
    }

    const int BadRequests::_code() const
    {
        return 400;
    }

    const std::string BadRequests::_status() const
    {
        return "bad_requests";
    }

} // namespace engine::server::gateway::responses