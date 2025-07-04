#pragma once

#include <engine/configuration/exception.hxx>
#include <engine/configuration/extend/configuration.hxx>
#include <engine/interfaces/iluaopenlibrary.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/json/json.hxx>
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
            const parser::Json tojson();

            [[nodiscard]] toml::node_view<const toml::node> get(
                const std::string &path) const;

          private:
            std::string m_path;
            toml::table m_toml;
        };
    } // namespace configuration
} // namespace engine