#pragma once

#include <cstdint>
#include <engine/parser/toml.hxx>
#include <string>

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

        namespace yara
        {
            struct Rule {
                std::string malware_path;
                std::string packed_path;
                std::string cve_path;
            };

            typedef struct Yara {
                Rule rules; // Seção de regras
            } Yara;
        } // namespace yara

        namespace clamav
        {
            struct Database {
                std::string default_path;
            };

            typedef struct Clamav {
                Database database;
            } Clamav;
        } // namespace clamav

        namespace sig
        {
            struct Rules {
                std::string packed_path;
            };

            typedef struct Sig {
                Rules rules; // Seção de regras
            } Sig;
        } // namespace sig

        namespace log
        {
            typedef struct Daily {
                uint16_t hours;
                uint16_t minutes;
                uint16_t max_size; // for 'rotating' type
            } Daily;

            typedef struct Rotation {
                uint16_t max_files;
                uint16_t max_size;
            } Rotation;

            typedef struct TraceUpdates {
                uint16_t interval;
            } TraceUpdates;

            typedef struct Log {
                std::string name;
                bool console;
                uint16_t level;
                TraceUpdates trace;
                std::string type;
                Daily daily_settings;
                Rotation rotation_settings;
            } Log;

        } // namespace log

        namespace crowapp
        {
            namespace server
            {
                typedef struct Context {
                    toml::array whitelist;
                } Context;

                typedef struct Server {
                    std::string bindaddr;
                    uint16_t port;
                    uint16_t threads;
                    std::string ssl_certificate_path;
                    Context context;
                } Server;

            } // namespace server

            typedef struct CrowApp {
                server::Server server;
            } CrowApp;
        } // namespace crowapp

        namespace cache
        {
            typedef struct Cache {
                std::string type;
                std::string path;
            } Cache;
        } // namespace cache

    } // namespace record
} // namespace configuration