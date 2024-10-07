#pragma once

#include <engine/configuration/entitys.hxx>
#include <engine/parser/toml.hxx>

namespace configuration
{
    class Configuration
    {
      public:
        Configuration(const std::string);
        ~Configuration();

        void load();
        const std::string &get_path_config() const ;
        const record::Cache &get_cache() const;
        const record::Clamav &get_clamav() const;
        const record::Project &get_project() const;
        const record::Yara &get_yara() const;
        const record::Log &get_log() const;
        const record::Sig &get_sig() const;
        const record::CrowApp &get_crowapp() const;


      private:
        const std::string m_path_config;
        parser::Toml m_toml;
        
        record::Cache m_cache;
        record::Clamav m_clamav;
        record::Project m_project;
        record::Yara m_yara;
        record::Log m_log;
        record::Sig m_sig;
        record::CrowApp m_crowapp;

        void load_cache();
        void load_clamav();
        void load_project();
        void load_sig();
        void load_crowapp();
        void load_yara();
        void load_log();
    };
} // namespace configuration