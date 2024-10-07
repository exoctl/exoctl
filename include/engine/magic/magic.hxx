#pragma once

#include <magic.h>
#include <string>

namespace magic
{
    class Magic
    {
      public:
        Magic();
        ~Magic();
        void load_mime(const std::string &buffer);
        [[nodiscard]] const std::string get_mime();

      private:
        magic_t m_cookie;
        std::string m_mime;
    };
} // namespace Magic
