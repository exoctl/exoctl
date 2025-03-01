#pragma once

namespace engine::interface
{
    class IEndpoint
    {
      public:
        virtual ~IEndpoint() = default;
        virtual void load() const = 0;
    };
} // namespace engine::interface
