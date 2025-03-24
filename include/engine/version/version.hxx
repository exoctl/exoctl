#pragma once

#include <engine/version/extend/version.hxx>

#define CODE 256
#define MAJOR 1
#define PATCHLEVEL 0
#define SUBLEVEL 0

namespace engine
{
    namespace version
    {
        class Version;

        class Version
        {
          public:
#ifdef ENGINE_PRO
            friend class version::extend::Version;
#endif
            Version() = default;
            ~Version() = default;

            static const int version(const int a, const int b, const int c);
        };
    } // namespace version
} // namespace engine