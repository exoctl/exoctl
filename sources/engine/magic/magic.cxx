#include <engine/magic/exception.hxx>
#include <engine/magic/magic.hxx>
#include <engine/memory/memory.hxx>

namespace engine
{
    namespace magic
    {
        Magic::Magic() : cookie_(magic_open(MAGIC_MIME))
        {
            if (IS_NULL(cookie_))
                throw magic::exception::Initialize(
                    "magic_open() failed to return a cookie");

            if (magic_load(cookie_, nullptr) != 0)
                throw magic::exception::Initialize(
                    "magic_load() failed to load magic database");
        }

        Magic::~Magic()
        {
            std::lock_guard<std::mutex> lock(mutex_);
            magic_close(cookie_);
        }

        const char *Magic::mime(const std::string &p_buffer)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            return magic_buffer(cookie_, p_buffer.c_str(), p_buffer.size());
        }
    } // namespace magic
} // namespace engine