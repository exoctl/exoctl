#include <engine/parser/toml.hxx>

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

    const toml::table &Toml::get_tbl() const
    {
        return m_tbl;
    }
    /*
    const std::string Toml::get_tbl_string(const std::string &p_tbl,
                                           const std::string &p_key)
    {
        return m_tbl[p_tbl][p_key].value<std::string>().value();
    }

    const std::uint16_t Toml::get_tbl_uint16(const std::string &p_tbl,
                                             const std::string &p_key)
    {
        return m_tbl[p_tbl][p_key].value<std::uint16_t>().value();
    }

    const toml::array Toml::get_tbl_array(const std::string &p_tbl,
                                          const std::string &p_key)
    {
        return *m_tbl[p_tbl][p_key].as_array();
    }

    const std::string Toml::get_tbl_string(const std::string &p_key)
    {
        return m_tbl[p_key].value<std::string>().value();
    }

    const std::uint16_t Toml::get_tbl_uint16(const std::string &p_key)
    {
        return m_tbl[p_key].value<std::uint16_t>().value();
    }

    const toml::array Toml::get_tbl_array(const std::string &p_key)
    {
        return *m_tbl[p_key].as_array();
    }

    const bool Toml::get_tbl_bool(const std::string &p_tbl,
                                  const std::string &p_key)
    {
        return m_tbl[p_tbl][p_key].value<bool>().value();
    }
*/
} // namespace parser