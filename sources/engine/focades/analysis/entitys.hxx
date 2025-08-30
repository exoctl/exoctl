#pragma once

#include <engine/database/entitys.hxx>
#include <string>

namespace engine::focades::analysis
{
    namespace record
    {
        struct File {
            std::string filename;
            std::string content; // buffer for scan
            std::string owner;
        };
    } // namespace record
} // namespace engine::focades::analysis