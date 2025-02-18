#pragma once

#include <cstdint>
#include <engine/parser/toml.hxx>
#include <string>

namespace engine::configuration::record
{
    namespace plugins
    {
        namespace lua
        {
            typedef struct Standard {
                std::vector<std::string> libraries;
            } Standard;
            typedef struct Lua {
                Standard standard;
            } Lua;
        } // namespace lua

        typedef struct Plugins {
            std::string path;
            bool enable;
            lua::Lua lua;
        } Plugins;
    } // namespace plugins

    namespace decompiler
    {
        struct Llama {
            std::string model;
        };
        typedef struct Decompiler {
            Llama llama;
        } Decompiler;
    } // namespace decompiler

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

    namespace llama
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

        typedef struct Llama {
            _::Log::Log log;
        } Llama;
    } // namespace llama

    namespace yara
    {
        namespace rules
        {
            struct Rules {
                std::string path;
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

            namespace database
            {
                struct Database {
                    std::string default_path;
                };
            } // namespace database

            typedef struct Clamav {
                database::Database database;
                _::log::Log log;
            } Clamav;
        } // namespace clamav
    } // namespace av

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
            unsigned int level;
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
                    unsigned int level;
                    std::string name;
                } Log;
            } // namespace log
        } // namespace _

        typedef struct Server {
            _::log::Log log;
            std::string name;
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
} // namespace engine::configuration::record
