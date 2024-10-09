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

        namespace log
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

            typedef struct Log {
                std::string name;
                std::string type;
                bool console;
                uint16_t level;
                traceupdates::TraceUpdates trace;
                daily::Daily daily_settings;
                rotation::Rotation rotation_settings;
            } Log;

        } // namespace log

        namespace crowapp
        {
            namespace server
            {
                namespace websocket
                {
                    namespace context
                    {
                        typedef struct Context {
                            toml::array whitelist;
                        } Context;
                    } // namespace context
                } // namespace websocket

                typedef struct Server {
                    std::string bindaddr;
                    uint16_t port;
                    uint16_t threads;
                    std::string ssl_certificate_path;
                    websocket::context::Context context;
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