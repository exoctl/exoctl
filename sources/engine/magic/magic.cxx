#include <engine/magic/exception.hxx>
#include <engine/magic/magic.hxx>
#include <engine/memory.hxx>

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
            magic_close(m_cookie);
        }

        void Magic::load_mime(const std::string &p_buffer)
        {
            m_mime = magic_buffer(m_cookie, p_buffer.c_str(), p_buffer.size());
        }

        const std::string Magic::get_mime()
        {
            return m_mime;
        }
    } // namespace magic
} // namespace engine