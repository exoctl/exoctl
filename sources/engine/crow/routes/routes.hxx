#pragma once

#include <engine/crow/crow.hxx>
#include <engine/crow/focades/analysis/scan/yara/yara.hxx>
#include <engine/crow/focades/data/metadata.hxx>
#include <engine/crow/focades/parser/binary/elf/elf.hxx>
#include <engine/crow/focades/rev/disassembly/capstone.hxx>
#include <engine/crow/routes/routes_types.hxx>
#include <engine/crow/routes/web/web.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>
#include <engine/version.hxx>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

// Helper macros for stringification
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Version and base API prefixes
#define VERSION_PREFIX "/v" TOSTRING(ENGINE_VERSION_MAJOR)
#define API_PREFIX VERSION_PREFIX "/engine"

template <typename... Args>
std::string concatenate_paths(const std::string &p_base, Args &&...p_args)
{
    std::string result = p_base;
    ((result.append(p_args)), ...);
    return result;
}

// Macro to define routes with variable prefixes
#define DEFINE_ROUTE(route, ...)                                                \
    static const std::string ROUTE_##route =                                    \
        concatenate_paths(API_PREFIX, __VA_ARGS__);

#define GET_ROUTE(route)                                                       \
    Routes::routes_##route();                                                  \
    m_num_endpoints++;

namespace Crow
{
    class Routes
    {
      public:
        Routes(CrowApp &);
        ~Routes();

        void routes_init();
        const std::vector<Crow::Structs::Endpoints> &routes_get_endpoints();

      private:
        CrowApp &m_crow;
        std::vector<Structs::Endpoints> m_endpoints;
        std::size_t m_num_endpoints;

        std::unique_ptr<WebSocket> m_socket_scan_yara;
        std::unique_ptr<WebSocket> m_socket_parser_elf;
        std::unique_ptr<WebSocket> m_socket_metadata;
        std::unique_ptr<WebSocket> m_socket_capstone_disass_x86_64;
        std::unique_ptr<WebSocket> m_socket_capstone_disass_arm_64;
        std::unique_ptr<Web<>> m_web_endpoins;

        std::unique_ptr<Focades::Parser::Binary::ELF> m_parser_elf;
        std::unique_ptr<Focades::Analysis::Scan::Yara> m_scan_yara;
        std::unique_ptr<Focades::Rev::Disassembly::Capstone> m_capstone_x86_64;
        std::unique_ptr<Focades::Rev::Disassembly::Capstone> m_capstone_arm_64;
        std::unique_ptr<Focades::Data::Metadata> m_metadata;

        void routes_update_endpoints();
        void routes_parser_elf();
        void routes_metadata();
        void routes_scan_yara();
        void routes_capstone_disass_x86_64();
        void routes_capstone_disass_arm_64();

        /* Routes generate for debug */
#ifdef DEBUG
        void routes_endpoint();
#endif
    };
} // namespace Crow
