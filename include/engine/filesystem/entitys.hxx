#pragma once

#include <string>

namespace engine::filesystem
{
    namespace type
    {
        enum class EnqueueTaskAction {
            WRITE,
            REMOVE
        };
    } // namespace type

    namespace record
    {
        using File = struct File {
            std::string filename;
            std::string content; // buffer for scan
        };

        using EnqueueTask = struct EnqueueTask {
            int id; // auto generated
            File file;
            type::EnqueueTaskAction action;
            bool relative = true; // path relative to filesystem.path
        };

    } // namespace record
} // namespace engine::filesystem
