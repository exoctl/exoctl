#pragma once

#include <any>
#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/toml.hxx>
#include <engine/configuration/exception.hxx>
#include <unordered_map>

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

            template <typename T> T get(const std::string &path) const
            {
                std::istringstream path_stream(path);
                std::string section;
                const std::unordered_map<std::string, std::any>
                    *current_section = &dynamic_configs;

                while (std::getline(path_stream, section, '.')) {
                    auto it = current_section->find(section);
                    if (it == current_section->end()) {
                        throw exception::Get("Section or key not found: " +
                                             section);
                    }

                    if (path_stream.eof()) {
                        try {
                            return std::any_cast<T>(it->second);
                        } catch (const std::bad_any_cast &) {
                            throw exception::Get("Type mismatch for key: " +
                                                 section);
                        }
                    }

                    try {
                        current_section = &std::any_cast<
                            const std::unordered_map<std::string, std::any> &>(
                            it->second);
                    } catch (const std::bad_any_cast &) {
                        throw exception::Get("Invalid path: " + path);
                    }
                }
                throw exception::Get("Invalid path: " + path);
            }
#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
          private:
            std::string m_path;
            std::unordered_map<std::string, std::any> dynamic_configs;
            parser::Toml m_toml;
        };
    } // namespace configuration
} // namespace engine