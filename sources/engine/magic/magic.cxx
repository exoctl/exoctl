#include <engine/magic/exception.hxx>
#include <engine/magic/magic.hxx>
#include <engine/memory/memory.hxx>
#include <engine/plugins/plugins.hxx>

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

#ifdef ENGINE_PRO
        void Magic::_plugins()
        {
            plugins::Plugins::lua.state.new_usertype<magic::Magic>(
                "Magic",
                sol::constructors<magic::Magic()>(),
                "load_mime",
                &Magic::load_mime,
                "mime",
                sol::readonly(&Magic::mime));
        }
#endif

        void Magic::load_mime(const std::string &p_buffer)
        {
            mime = magic_buffer(m_cookie, p_buffer.c_str(), p_buffer.size());
        }
    } // namespace magic
} // namespace engine