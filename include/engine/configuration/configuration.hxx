#pragma once

#include <any>
#include <engine/configuration/entitys.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/toml.hxx>
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

#ifdef ENGINE_PRO
            void register_plugins() override;
            record::plugins::Plugins plugins;
#endif
            record::lief::Lief lief;
            record::llama::Llama llama;
            record::av::clamav::Clamav av_clamav;
            record::Project project;
            record::yara::Yara yara;
            record::logging::Logging logging;
            record::server::Server server;
            record::decompiler::Decompiler decompiler;
            /*
             end sections
            */
          protected:
            parser::Toml m_toml;

          private:
            std::string m_path;

            void load_llama();
            void load_av_clamav();
            void load_project();
            void load_sig();
            void load_server();
            void load_yara();
            void load_logging();
            void load_lief();
            void load_decompiler();
            void load_plugins();
        };

        struct DynConfig : public Configuration {
          public:
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
                        throw std::runtime_error("Section or key not found: " +
                                                 section);
                    }

                    if (path_stream.eof()) {
                        try {
                            return std::any_cast<T>(it->second);
                        } catch (const std::bad_any_cast &) {
                            throw std::runtime_error("Type mismatch for key: " +
                                                     section);
                        }
                    }

                    try {
                        current_section = &std::any_cast<
                            const std::unordered_map<std::string, std::any> &>(
                            it->second);
                    } catch (const std::bad_any_cast &) {
                        throw std::runtime_error("Invalid path: " + path);
                    }
                }
                throw std::runtime_error("Invalid path: " + path);
            }

          private:
            std::unordered_map<std::string, std::any> dynamic_configs;
        };

    } // namespace configuration
} // namespace engine