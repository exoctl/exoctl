#pragma once

#include <engine/crow/controllers/analysis/scan_yara.hxx>
#include <engine/crow/controllers/data/metadata.hxx>
#include <engine/crow/controllers/rev/disassembly_capstone.hxx>
#include <engine/crow/crow.hxx>
#include <engine/crow/routes/routes_types.hxx>
#include <engine/crow/routes/web/web.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>
#include <list>

namespace Crow
{
#define GET_ROUTE(route) Routes::route_##route();

struct route
{
    const std::string r_path;
    const Types::Routes_t r_type;
    const uint64_t r_connections;
};

class Routes
{
  public:
    Routes(CrowApp &);
    ~Routes();

    void routes_init();
    void routes_update_route();
    std::list<route>& routes_get_routes();

  private:
    CrowApp &m_crow;
    std::list<route> m_routes;

    WebSocket *m_socket_scan_yara;
    WebSocket *m_socket_metadata;
    WebSocket *m_socket_capstone_disass_x86_64;
    WebSocket *m_socket_capstone_disass_arm_64;
    Web<> *m_web_routes;

    Controllers::Analysis::ScanYara *m_scan_yara;
    Controllers::Rev::Capstone *m_capstone_x86_64;
    Controllers::Rev::Capstone *m_capstone_arm_64;
    Controllers::Data::Metadata *m_metadata;

    void route_metadata();
    void route_scan_yara();
    void route_capstone_disass_x86_64();
    void route_capstone_disass_arm_64();
    void route_routes();
};
} // namespace Crow
