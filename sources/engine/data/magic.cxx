#include <engine/data/data_exception.hxx>
#include <engine/data/magic.hxx>

namespace Data
{
Magic::Magic() : m_cookie(magic_open(MAGIC_MIME))
{
    if (m_cookie == nullptr)
        throw DataException::Initialize(
            "magic_open() failed to return a cookie");

    if (magic_load(m_cookie, nullptr) != 0)
        throw DataException::Initialize(
            "magic_load failed to load magic database");
}
Magic::~Magic() { magic_close(m_cookie); }

const void Magic::magic_load_mime(const std::string &p_buffer)
{
    m_mime = magic_buffer(m_cookie, p_buffer.c_str(), p_buffer.size());
}

const std::string Magic::magic_get_mime() { return m_mime; }
} // namespace Data
