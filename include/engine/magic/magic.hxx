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
        magic_t m_cookie;
        std::mutex m_mutex;
    };
} // namespace engine::magic
