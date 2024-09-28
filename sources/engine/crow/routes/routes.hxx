#pragma once

#include <engine/crow/crow.hxx>
#include <engine/crow/focades/analysis/scan_yara/scan_yara.hxx>
#include <engine/crow/focades/data/metadata.hxx>
#include <engine/crow/focades/parser/elf.hxx>
#include <engine/crow/focades/rev/disassembly_capstone.hxx>
#include <engine/crow/routes/routes_types.hxx>
#include <engine/crow/routes/web/web.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>
#include <functional>
#include <vector>

#define GET_ROUTE(route)                                                       \
    Routes::route_##route();                                                   \
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

        //Focades::Parser::ELF *m_parser_elf;
        Focades::Analysis::ScanYara *m_scan_yara;
        Focades::Rev::Capstone *m_capstone_x86_64;
        Focades::Rev::Capstone *m_capstone_arm_64;
        Focades::Data::Metadata *m_metadata;

        void route_parser_elf();
        void routes_update_endpoints();
        void route_metadata();
        void route_scan_yara();
        void route_capstone_disass_x86_64();
        void route_capstone_disass_arm_64();

        /* Routes generate for debug */
#ifdef DEBUG
        void route_endpoint();
#endif
    };
} // namespace Crow
