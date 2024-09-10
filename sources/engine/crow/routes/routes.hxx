#pragma once

#include <engine/crow/crow.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>
#include <engine/external/analysis/scan_yara.hxx>
#include <engine/external/data/metadata.hxx>
#include <engine/external/rev/disassembly_capstone_x86_64.hxx>

#include <mutex>

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

    WebSocket *socket_scan_yara;
    WebSocket *socket_metadata;
    WebSocket *socket_capstone_disass;

    void route_init_analysis();
};
} // namespace Crow
