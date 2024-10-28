#pragma once

#include <cstdint>
#include <engine/parser/toml.hxx>
#include <string>
namespace engine
{
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

            namespace lief
            {
                namespace _
                {
                    namespace Log
                    {
                        struct Log {
                            int level;
                            std::string name;
                        };
                    } // namespace Log
                } // namespace _

                typedef struct Lief {
                    _::Log::Log log;
                } Lief;
            } // namespace lief

            namespace yara
            {
                namespace rules
                {
                    struct Rules {
                        std::string malware_path;
                        std::string packed_path;
                        std::string cve_path;
                    };
                } // namespace rules

                typedef struct Yara {
                    rules::Rules rules; // Seção de regras
                } Yara;
            } // namespace yara

            namespace av
            {
                namespace clamav
                {
                    namespace database
                    {
                        struct Database {
                            std::string default_path;
                        };
                    } // namespace database

                    typedef struct Clamav {
                        database::Database database;
                    } Clamav;
                } // namespace clamav
            } // namespace av

            namespace sig
            {
                namespace rules
                {
                    struct Rules {
                        std::string packed_path;
                    };
                } // namespace rules
                typedef struct Sig {
                    rules::Rules rules; // Seção de regras
                } Sig;
            } // namespace sig

            namespace logging
            {
                namespace daily
                {
                    typedef struct Daily {
                        uint16_t hours;
                        uint16_t minutes;
                        uint16_t max_size; // for 'rotating' type
                    } Daily;
                } // namespace daily

                namespace rotation
                {
                    typedef struct Rotation {
                        uint16_t max_files;
                        uint16_t max_size;
                    } Rotation;
                } // namespace rotation

                namespace traceupdates
                {
                    typedef struct TraceUpdates {
                        uint16_t interval;
                    } TraceUpdates;
                } // namespace traceupdates

                typedef struct Logging {
                    std::string filepath;
                    std::string name;
                    std::string pattern;
                    std::string type;
                    bool console;
                    int level;
                    traceupdates::TraceUpdates trace;
                    daily::Daily daily_settings;
                    rotation::Rotation rotation_settings;
                } Log;

            } // namespace logging

            namespace server
            {
                namespace _
                {
                    namespace log
                    {
                        typedef struct Log {
                            int level;
                            std::string name;
                        } Log;
                    } // namespace log
                } // namespace _

                typedef struct Server {
                    _::log::Log log;
                    std::string bindaddr;
                    uint16_t port;
                    uint16_t threads;
                    std::string ssl_certificate_path;
                } Server;
            } // namespace server

            namespace cache
            {
                typedef struct Cache {
                    std::string type;
                    std::string path;
                } Cache;
            } // namespace cache

        } // namespace record
    } // namespace configuration
} // namespace engine