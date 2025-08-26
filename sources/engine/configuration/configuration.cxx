#include <engine/configuration/configuration.hxx>
#include <engine/configuration/exception.hxx>
#include <engine/plugins/plugins.hxx>
#include <fmt/core.h>

namespace engine
{
    namespace configuration
    {
        void Configuration::setup(const std::string &p_path)
        {
            path_.assign(p_path);
        }

        const parser::json::Json Configuration::tojson()
        {
            std::ostringstream oss;
            parser::json::Json json;

            oss << toml::json_formatter{toml_};
            json.from_string(oss.str());
            return json;
        }

        void Configuration::load()
        {
            TRY_BEGIN()

            toml_ = toml::parse_file(path_);

            TRY_END()
            CATCH(toml::parse_error, {
                const auto &source = e.source();
                throw exception::Load(
                    fmt::format("Configuration error file '{:s}' at line {:d}, "
                                "column {:d}: {:s}",
                                *source.path,
                                source.begin.line,
                                source.begin.column,
                                e.description()));
            })
            CATCH(std::exception, {
                throw exception::Load(
                    fmt::format("Unexpected error: {:s}", e.what()));
            });
        }

        toml::node_view<const toml::node> Configuration::get(
            const std::string &path) const
        {
            auto node = toml_.at_path(path);
            if (!node) {
                throw exception::Get("Section or key not found: " + path);
            }
            return node;
        }

        Configuration &Configuration::operator=(const Configuration &p_config)
        {
            if (this != &p_config) {
                path_ = p_config.path_;
                toml_ = p_config.toml_;
            }
            return *this;
        }
    } // namespace configuration
} // namespace engine