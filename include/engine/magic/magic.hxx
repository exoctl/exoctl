#pragma once

#include <magic.h>
#include <string>

namespace Magic
{
class Magic
{
  public:
    Magic();
    ~Magic();
    const void magic_load_mime(const std::string &buffer);
    const std::string magic_get_mime();

  private:
    magic_t m_cookie;
    std::string m_mime;
};
} // namespace Data
