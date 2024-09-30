#pragma once

#include <engine/crow/crow.hxx>
#include <engine/crow/focades/analysis/scan/yara/yara.hxx>
#include <engine/crow/focades/data/metadata.hxx>
#include <engine/crow/focades/parser/binary/elf/elf.hxx>
#include <engine/crow/focades/rev/disassembly/capstone.hxx>
#include <engine/crow/routes/routes_types.hxx>
#include <engine/crow/routes/web/web.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>
#include <functional>
#include <vector>

#define GET_ROUTE(route)                                                       \
    Routes::routes_##route();                                                   \
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

        WebSocket *m_socket_scan_yara;
        WebSocket *m_socket_parser_elf;
        WebSocket *m_socket_metadata;
        WebSocket *m_socket_capstone_disass_x86_64;
        WebSocket *m_socket_capstone_disass_arm_64;
        Web<> *m_web_endpoins;

        Focades::Parser::Binary::ELF *m_parser_elf;
        Focades::Analysis::Scan::Yara *m_scan_yara;
        Focades::Rev::Disassembly::Capstone *m_capstone_x86_64;
        Focades::Rev::Disassembly::Capstone *m_capstone_arm_64;
        Focades::Data::Metadata *m_metadata;

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
