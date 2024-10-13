#pragma once

namespace engine
{
    namespace interface
    {
        class IGateway
        {
          public:
            virtual ~IGateway() = default;
            virtual void load() const = 0;
        };
    } // namespace interface
} // namespace engine