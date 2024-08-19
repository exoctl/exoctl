#pragma once

#include "uinterfaces.hxx"
#include <string>
#include <functional>

namespace Database
{
    abstract_class IDB
    {
    public:
        IDB(){};
        virtual ~IDB(){};

        virtual const bool open_db() const = 0;
        virtual const bool is_open_db() const = 0;
        virtual const void exec_query_commit(const std::string &) const = 0;
        virtual const void exec_query(const std::string &, const std::function<void(void *)> &) const = 0;
        virtual const void close_db() const = 0;
    };
}