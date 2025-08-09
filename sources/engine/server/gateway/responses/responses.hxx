#pragma once

#include <engine/interfaces/iresponse.hxx>

namespace engine::server::gateway::responses
{
    class Connected : public interface::IResponse<Connected>
    {
      public:
        Connected() = default;
        ~Connected() override = default;

        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };

    class UnsupportedData : public interface::IResponse<UnsupportedData>
    {
      public:
        UnsupportedData() = default;
        ~UnsupportedData() override = default;

        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };

    class Accepted : public interface::IResponse<Accepted>
    {
      public:
        Accepted() = default;
        ~Accepted() override = default;

        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };

    class InvalidTokenJWT : public interface::IResponse<InvalidTokenJWT>
    {
      public:
        InvalidTokenJWT() = default;
        ~InvalidTokenJWT() override = default;

        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };

    class BadRequests : public interface::IResponse<BadRequests>
    {
      public:
        BadRequests() = default;
        ~BadRequests() override = default;

        const int _code() const override;
        const std::string _status() const override;
        const std::string _message() const override;
    };
} // namespace engine::server::gateway::responses
