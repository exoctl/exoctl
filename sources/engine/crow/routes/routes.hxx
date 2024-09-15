#pragma once

#include <engine/crow/controllers/analysis/scan_yara.hxx>
#include <engine/crow/controllers/data/metadata.hxx>
#include <engine/crow/controllers/rev/disassembly_capstone.hxx>
#include <engine/crow/crow.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>

namespace Crow
{
#define GET_ROUTE(route) Routes::route_##route();
class Routes
{
  public:
    Routes(CrowApp &);
    ~Routes();

    void routes_init();

  private:
    CrowApp &m_crow;

    WebSocket *m_socket_scan_yara;
    WebSocket *m_socket_metadata;
    WebSocket *m_socket_capstone_disass_x86_64;
    WebSocket *m_socket_capstone_disass_arm_64;

    Controllers::Analysis::ScanYara *m_scan_yara;
    Controllers::Rev::Capstone *m_capstone_x86_64;
    Controllers::Rev::Capstone *m_capstone_arm_64;
    Controllers::Data::Metadata *m_metadata;

    void route_metadata();
    void route_scan_yara();
    void route_capstone_disass_x86_64();
    void route_capstone_disass_arm_64();
};
} // namespace Crow
