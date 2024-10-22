#pragma once

#include <engine/interfaces/iresponse.hxx>

namespace engine::crowapp::bridge::gateway::websocket::responses
{
    class Connected : public interface::IResponse
    {
      public:
        Connected();
        ~Connected() = default;

        const parser::Json to_json() const override;
        const int code() const override;
        const std::string status() const override;
    };

} // namespace engine::crowapp::bridge::gateway::websocket::responses