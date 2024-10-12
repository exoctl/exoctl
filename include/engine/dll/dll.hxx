#pragma once

#include <dlfcn.h>
#include <functional>
#include <link.h>

namespace engine
{
    namespace dll
    {
        class Dll
        {
          public:
            Dll();
            ~Dll();

            [[nodiscard]] const void *open(const char *, int);
            [[nodiscard]] const int close(void *);
            void info(void *,
                      int,
                      const std::function<void(struct link_map &)> &);
        };
    } // namespace dll
} // namespace engine