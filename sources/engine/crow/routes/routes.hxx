#pragma once

#include <engine/crow/conn/conn.hxx>
#include <engine/crow/crow.hxx>
#include <engine/crow/routes/websocket.hxx>
#include <engine/external/analysis/scan_yara.hxx>
#include <engine/external/data/metadata.hxx>
#include <engine/external/rev/disassembly_capstone_x86_64.hxx>

#include <mutex>

#define GET_ROUTE(name) Routes::route_##name();

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
    Context m_context;

    Data::Metadata m_metadata;
    Analysis::ScanYara m_scan_yara;
    Rev::CapstoneX86 m_capstonex86;

    std::mutex m_mtx;

    void route_init_analysis();
};
} // namespace Crow
