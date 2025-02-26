#pragma once

#include <any>
#include <engine/configuration/exception.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <toml++/toml.hpp>
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
                auto node = m_toml.at_path(path);
                if (!node) {
                    throw exception::Get("Section or key not found: " + path);
                }

                if constexpr (std::is_same_v<T, toml::array>) {
                    auto *arr = node.as_array();
                    if (!arr) {
                        throw exception::Get(
                            "Type mismatch: expected array for key: " + path);
                    }
                    return *arr;
                } else {
                    auto value = node.value<T>();
                    if (!value) {
                        throw exception::Get("Type mismatch for key: " + path);
                    }
                    return *value;
                }
            }

#ifdef ENGINE_PRO
            void register_plugins() override;
#endif
          private:
            std::string m_path;
            toml::table m_toml;
        };
    } // namespace configuration
} // namespace engine