#pragma once

namespace interface
{
    class IGateway
    {
      public:
        virtual ~IGateway() = default;
        virtual void load() const = 0;
    };
} // namespace interface