#pragma once

#include <engine/crowapp/bridge/entitys.hxx>
#include <engine/crowapp/bridge/web/web.hxx>
#include <engine/crowapp/bridge/websocket/websocket.hxx>
#include <engine/crowapp/crowapp.hxx>
#include <engine/crowapp/focades/analysis/scan/clamav/clamav.hxx>
#include <engine/crowapp/focades/analysis/scan/yara/yara.hxx>
#include <engine/crowapp/focades/data/metadata/metadata.hxx>
#include <engine/crowapp/focades/parser/binary/elf/elf.hxx>
#include <engine/crowapp/focades/rev/disassembly/capstone/capstone.hxx>
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
#define DEFINE_ROUTE(route, ...)                                               \
    static const std::string ROUTE_##route =                                   \
        concatenate_paths(API_PREFIX, __VA_ARGS__);

#define GET_ROUTE(route)                                                       \
    Bridge::route();                                                         \
    m_num_endpoints++;

namespace crowapp
{
    class Bridge
    {
      public:
        Bridge(CrowApp &);
        ~Bridge();

        void load();
        const std::vector<bridge::record::Bridge> &get_endpoints();

      private:
        CrowApp &m_crow;
        std::vector<bridge::record::Bridge> m_endpoints;
        std::size_t m_num_endpoints;

        std::unique_ptr<crowapp::bridge::WebSocket> m_socket_scan_yara;
        std::unique_ptr<crowapp::bridge::WebSocket> m_socket_parser_elf;
        std::unique_ptr<crowapp::bridge::WebSocket> m_socket_metadata;
        std::unique_ptr<crowapp::bridge::WebSocket> m_socket_clamav;
        std::unique_ptr<crowapp::bridge::WebSocket>
            m_socket_capstone_disass_x86_64;
        std::unique_ptr<crowapp::bridge::WebSocket>
            m_socket_capstone_disass_arm_64;
        std::unique_ptr<crowapp::bridge::Web<>> m_web_endpoins;

        std::unique_ptr<focades::parser::binary::ELF> m_parser_elf;
        std::unique_ptr<focades::analysis::scan::Yara> m_scan_yara;
        std::unique_ptr<focades::analysis::scan::Clamav> m_scan_clamav;
        std::unique_ptr<focades::rev::disassembly::Capstone> m_capstone_x86_64;
        std::unique_ptr<focades::rev::disassembly::Capstone> m_capstone_arm_64;
        std::unique_ptr<focades::data::Metadata> m_metadata;

        void update_endpoints();
        void parser_elf();
        void metadata();
        void scan_yara();
        void capstone_disass_x86_64();
        void capstone_disass_arm_64();
        void scan_clamav();

        /* Routes generate for debug */
#ifdef DEBUG
        void endpoint();
#endif
    };
} // namespace crowapp
