#pragma once

#include <engine/version/extend/version.hxx>

#define ENGINE_CODE 259
#define ENGINE_MAJOR 1
#define ENGINE_MINOR 3
#define ENGINE_PATCH 0

namespace engine
{
    namespace version
    {
        class Version;

        class Version
        {
          public:
            friend class version::extend::Version;

            Version() = default;
            ~Version() = default;

            static const int check(const int a, const int b, const int c);
        };
    } // namespace version
} // namespace engine