#pragma once

#include <engine/configuration/exception.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <toml++/toml.hpp>

namespace engine
{
    namespace configuration
    {
        class Configuration : public interface::IBind
#ifdef ENGINE_PRO
            ,
                              public interface::IPlugins
#endif
        {
          public:
            Configuration() = default;
            ~Configuration() = default;
            Configuration &operator=(const Configuration &);

            void bind_to_lua(sol::state_view &) override;
            void setup(const std::string &);
            void load();

            [[nodiscard]] toml::node_view<const toml::node> get(
                const std::string &path) const;

#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
          private:
            std::string m_path;
            toml::table m_toml;
        };
    } // namespace configuration
} // namespace engine