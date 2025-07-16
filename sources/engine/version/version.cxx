#include <engine/version/version.hxx>

namespace engine
{
    namespace version
    {
        const int Version::check(const int a, const int b, const int c)
        {
            return ((a << 16) + (b << 8) + (c > 255 ? 255 : c));
        }
    } // namespace version
} // namespace engine