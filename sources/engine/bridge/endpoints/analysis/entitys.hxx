#pragma once

#include <string>

namespace engine::bridge::endpoints::analysis
{
    namespace record
    {
        using EnqueueTask = struct EnqueueTask {
            int id; // auto generated
            std::string buf;
        };
    } // namespace record
} // namespace engine::filesystem
