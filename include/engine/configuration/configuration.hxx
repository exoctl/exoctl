#pragma once

#include <engine/configuration/entitys.hxx>
#include <engine/interfaces/ibind.hxx>
#include <engine/interfaces/iplugins.hxx>
#include <engine/parser/toml.hxx>

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

          private:
            std::string m_path;
            parser::Toml m_toml;

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
    } // namespace configuration
} // namespace engine