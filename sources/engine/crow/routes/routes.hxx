#pragma once

#include <engine/crow/crow.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>
#include <engine/external/analysis/scan_yara.hxx>
#include <engine/external/data/metadata.hxx>
#include <engine/external/rev/disassembly_capstone_arm64.hxx>
#include <engine/external/rev/disassembly_capstone_x86_64.hxx>

namespace Crow
{
class Routes
{
  public:
    Routes(CrowApp &);
    ~Routes();

    void routes_init();

  private:
    CrowApp &m_crow;

    Data::Metadata m_metadata;
    Analysis::ScanYara m_scan_yara;
    Rev::CapstoneX86 m_capstonex86;
    Rev::CapstoneARM64 m_capstonearm64;

    WebSocket *m_socket_scan_yara;
    WebSocket *m_socket_metadata;
    WebSocket *m_socket_capstone_disass_x86_64;
    WebSocket *m_socket_capstone_disass_arm64;

    void route_init_analysis();
};
} // namespace Crow
