#pragma once

#include <string>

namespace engine::filesystem
{
    namespace record
    {
        using File = struct File {
            std::string filename;
            std::string content; // buffer for scan
        };

        using EnqueueTask = struct EnqueueTask {
            int id; // auto generated
            File file;
        };

    } // namespace record
} // namespace engine::filesystem
