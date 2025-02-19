#pragma once

#include <engine/interfaces/iplugins.hxx>
#include <magic.h>
#include <string>

namespace engine
{
    namespace magic
    {
        class Magic
#ifdef ENGINE_PRO
            : public interface::ISubPlugins<Magic>
#endif
        {
          public:
            Magic();
            ~Magic();
            void load_mime(const std::string &buffer);

#ifdef ENGINE_PRO
            void _plugins() override;
#endif

            std::string mime;

          private:
            magic_t m_cookie;
        };
    } // namespace magic
} // namespace engine