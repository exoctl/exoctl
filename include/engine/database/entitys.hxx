#pragma once

#include <string>

namespace engine::database
{
    namespace record
    {
        using EnqueueTask = struct EnqueueTask {
            int id; // auto generated
            std::string sql;
        };
    } // namespace record
} // namespace engine::database
