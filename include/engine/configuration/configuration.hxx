#pragma once

#include <engine/configuration/exception.hxx>
#include <engine/configuration/extend/configuration.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <toml++/toml.hpp>

namespace engine
{
    namespace configuration
    {
        class Configuration;

        class Configuration
        {
          public:
            Configuration() = default;
            ~Configuration() = default;
            Configuration &operator=(const Configuration &);

            friend class extend::Configuration;

            void setup(const std::string &);
            void load();

            [[nodiscard]] toml::node_view<const toml::node> get(
                const std::string &path) const;

          private:
            std::string m_path;
            toml::table m_toml;
        };
    } // namespace configuration
} // namespace engine