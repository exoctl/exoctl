#pragma once

#include <engine/parser/json.hxx>

namespace engine
{
    namespace interface
    {
        class IResponse
        {
          public:
            virtual ~IResponse() = default;
            virtual const parser::Json to_json() const = 0;
            virtual const int code() const = 0;
            virtual const std::string status() const = 0;
        };
    } // namespace interface
} // namespace engine