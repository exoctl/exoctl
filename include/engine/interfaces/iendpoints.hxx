#pragma once

namespace engine
{
    namespace interface
    {
        class IEndpoints
        {
          public:
            virtual ~IEndpoints() = default;
            virtual void load() const = 0;
        };
    } // namespace interface
} // namespace engine