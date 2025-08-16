#include <engine/magic/exception.hxx>
#include <engine/magic/magic.hxx>
#include <engine/memory/memory.hxx>

namespace engine
{
    namespace magic
    {
        Magic::Magic() : m_cookie(magic_open(MAGIC_MIME))
        {
            if (IS_NULL(m_cookie))
                throw magic::exception::Initialize(
                    "magic_open() failed to return a cookie");

            if (magic_load(m_cookie, nullptr) != 0)
                throw magic::exception::Initialize(
                    "magic_load() failed to load magic database");
        }

        Magic::~Magic()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            magic_close(m_cookie);
        }

        const char *Magic::mime(const std::string &p_buffer)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return magic_buffer(m_cookie, p_buffer.c_str(), p_buffer.size());
        }
    } // namespace magic
} // namespace engine