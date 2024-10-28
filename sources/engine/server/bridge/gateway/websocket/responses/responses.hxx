#pragma once

#include <engine/server/server.hxx>
#include <engine/interfaces/iresponse.hxx>

namespace engine::server::bridge::gateway::websocket::responses
{
    class Connected : public interface::IResponse<Connected>
    {
      public:
        Connected();
        ~Connected() override = default;

        const parser::Json _to_json() const override;
        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };

    class UnsupportedData : public interface::IResponse<UnsupportedData>
    {
      public:
        UnsupportedData();
        ~UnsupportedData() override = default;

        const parser::Json _to_json() const override;
        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };

    class InvalidTokenJWT : public interface::IResponse<InvalidTokenJWT>
    {
      public:
        InvalidTokenJWT();
        ~InvalidTokenJWT() override = default;

        const parser::Json _to_json() const override;
        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };
} // namespace engine::server::bridge::gateway::websocket::responses
