#include <engine/parser/toml.hxx>

namespace engine
{
    namespace parser
    {
        Toml::Toml()
        {
        }
        Toml::~Toml()
        {
        }

        void Toml::parse_file(const std::string &p_filepath)
        {
            m_tbl = toml::parse_file(p_filepath);
        }

        void Toml::parse_buffer(const std::string_view &p_buffer)
        {
            m_tbl = toml::parse(p_buffer);
        }

        const toml::table &Toml::get_tbl() const
        {
            return m_tbl;
        }
    } // namespace parser
} // namespace engine