#pragma once

#include <engine/crow/controllers/analysis/scan_yara.hxx>
#include <engine/crow/controllers/data/metadata.hxx>
#include <engine/crow/controllers/rev/disassembly_capstone.hxx>
#include <engine/crow/crow.hxx>
#include <engine/crow/routes/routes_types.hxx>
#include <engine/crow/routes/web/web.hxx>
#include <engine/crow/routes/websocket/websocket.hxx>
#include <functional>
#include <vector>

namespace Crow
{
#define GET_ROUTE(route)                                                       \
    Routes::route_##route();                                                   \
    m_num_endpoints++;

struct route
{
    const std::string path;
    const Types::Routes_t type;
    const uint64_t connections; /* only websocket connections */
};

class Routes
{
  public:
    Routes(CrowApp &);
    ~Routes();

    void routes_init();
    std::vector<route> &routes_get_endpoints();

  private:
    CrowApp &m_crow;
    std::vector<route> m_endpoints;
    std::size_t m_num_endpoints;

    WebSocket *m_socket_scan_yara;
    WebSocket *m_socket_metadata;
    WebSocket *m_socket_capstone_disass_x86_64;
    WebSocket *m_socket_capstone_disass_arm_64;
    Web<> *m_web_endpoins;

    Controllers::Analysis::ScanYara *m_scan_yara;
    Controllers::Rev::Capstone *m_capstone_x86_64;
    Controllers::Rev::Capstone *m_capstone_arm_64;
    Controllers::Data::Metadata *m_metadata;

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
