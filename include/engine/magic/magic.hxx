#pragma once

#include <engine/magic/extend/magic.hxx>
#include <magic.h>
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

        void load_mime(const std::string &buffer);

        std::string mime;

      private:
        magic_t m_cookie;
    };
} // namespace engine::magic
