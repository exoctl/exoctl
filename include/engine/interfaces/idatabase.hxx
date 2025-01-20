#pragma once

#include <functional>
#include <string>

namespace engine
{
    namespace interface
    {
        class IDatabase
        {
          public:
            IDatabase() {};
            virtual ~IDatabase() {};

            virtual const bool open_db() const = 0;
            virtual const bool is_open_db() const = 0;
            virtual void exec_query_commit(const std::string &) const = 0;
            virtual void exec_query(
                const std::string &,
                const std::function<void(void *)> &) const = 0;
            virtual void close_db() const = 0;
        };
    } // namespace interface
} // namespace engine