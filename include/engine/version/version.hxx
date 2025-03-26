#pragma once

#include <engine/version/extend/version.hxx>

#define CODE 256
#define ENGINE_MAJOR 1
#define ENGINE_MINOR 0
#define ENGINE_PATCH 0

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