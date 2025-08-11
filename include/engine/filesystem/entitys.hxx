#pragma once

#include <string>

namespace engine::filesystem
{
    namespace record
    {
        using EnqueueTask = struct EnqueueTask {
            int id; // auto generated
            const char *filename;
            std::string content;
        };
    } // namespace record
} // namespace engine::filesystem
