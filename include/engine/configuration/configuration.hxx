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
        const std::string &get_path_config() const;
        const record::cache::Cache &get_cache() const;
        const record::clamav::Clamav &get_clamav() const;
        const record::Project &get_project() const;
        const record::yara::Yara &get_yara() const;
        const record::log::Log &get_log() const;
        const record::sig::Sig &get_sig() const;
        const record::crowapp::CrowApp &get_crowapp() const;

      private:
        const std::string m_path_config;
        parser::Toml m_toml;

        record::cache::Cache m_cache;
        record::clamav::Clamav m_clamav;
        record::Project m_project;
        record::yara::Yara m_yara;
        record::log::Log m_log;
        record::sig::Sig m_sig;
        record::crowapp::CrowApp m_crowapp;

        void load_cache();
        void load_clamav();
        void load_project();
        void load_sig();
        void load_crowapp();
        void load_yara();
        void load_log();
    };
} // namespace configuration