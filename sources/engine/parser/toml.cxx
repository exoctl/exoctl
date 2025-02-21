#include <engine/parser/toml.hxx>

namespace engine
{
    namespace parser
    {
        void Toml::parse_file(const std::string &p_filepath)
        {
            tbl = toml::parse_file(p_filepath);
        }

        void Toml::parse_buffer(const std::string_view &p_buffer)
        {
            tbl = toml::parse(p_buffer);
        }

    } // namespace parser
} // namespace engine