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

        [[nodiscard]] virtual auto open_db() const -> const bool = 0;
        [[nodiscard]] virtual auto is_open_db() const -> const bool = 0;
        virtual void exec_query_commit(const std::string &) const = 0;
        virtual void exec_query(const std::string &,
                                const std::function<void(void *)> &) const = 0;
        virtual void close_db() const = 0;
    };
} // namespace engine::interface
