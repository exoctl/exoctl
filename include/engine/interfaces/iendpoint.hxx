#pragma once

namespace engine
{
    namespace interface
    {
        class IEndpoint
        {
          public:
            virtual ~IEndpoint() = default;
            virtual void load() const = 0;
        };
    } // namespace interface
} // namespace engine