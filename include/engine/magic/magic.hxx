#pragma once

#include <engine/magic/extend/magic.hxx>
#include <magic.h>
#include <mutex>
#include <string>

namespace engine::magic
{
    class Magic;

    class Magic
    {
      public:
        Magic();
        ~Magic();

        friend class extend::Magic;

        const char *mime(const std::string &buffer);

      private:
        magic_t cookie_;
        std::mutex mutex_;
    };
} // namespace engine::magic
