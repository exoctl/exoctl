#pragma once

#include <engine/analysis/scan_yara.hxx>
#include <engine/data/metadata.hxx>
#include <engine/crow/conn/conn.hxx>
#include <engine/crow/crow.hxx>
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
    std::mutex m_mtx;

    void route_search_yara();
    void route_scan_sig_packed();
    void route_scan_yara();
    void route_metadata();
    void route_def_close_connection(crow::websocket::connection *,
                                    const std::string &);
    void route_def_open_connection(crow::websocket::connection *);
    bool route_def_onaccept_connection(const crow::request *);
    void route_init_analysis();
};
} // namespace Crow
