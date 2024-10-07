#pragma once

#include <string>
#include <cstdint>
#include <engine/parser/toml.hxx>

namespace configuration
{
    namespace record
    {
        typedef struct Project {
            std::string name;
            std::string version;
            std::string description;
            std::string copyright;
        } Project;

        typedef struct Yara {
            std::string malware_rules;
            std::string packeds_rules;
            std::string cve_rules;
        } Yara;

        typedef struct Clamav {
            std::string default_database;
        } Clamav;

        typedef struct Sig {
            std::string packeds_rules;
        } Sig;

        typedef struct Log {
            std::string name;
            bool console;
            uint16_t level;
            uint16_t trace;
            std::string type;
            uint16_t max_files;
            uint16_t hours; // for 'day' type
            uint16_t minutes;
            uint16_t max_size; // for 'rotating' type
        } Log;

        typedef struct CrowApp {
            std::string bindaddr;
            uint16_t port;
            uint16_t threads;
            toml::array context_whitelist;
            std::string ssl_file_pem;
        } CrowApp;

        typedef struct Cache {
            std::string type;
            std::string name;
        } Cache;

    } // namespace record
} // namespace configuration