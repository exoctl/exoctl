#pragma once

#include <string>

namespace engine::focades::analysis
{
    namespace record
    {
        using EnqueueTask = struct EnqueueTask {
            int id; // auto generated
            std::string buf;
        };
    } // namespace record
} // namespace engine::focades::analysis
