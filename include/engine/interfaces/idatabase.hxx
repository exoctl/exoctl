#pragma once

#include <functional>
#include <string>

namespace engine::interface
{
    class IDatabase
    {
      public:
        IDatabase() = default;
        virtual ~IDatabase() = default;

        [[nodiscard]] virtual auto is_db_open() const -> const bool = 0;
        virtual void close_db() const = 0;
    };
} // namespace engine::interface
