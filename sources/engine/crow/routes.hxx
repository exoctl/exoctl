#pragma once

#include <engine/crow/conn.hxx>
#include <engine/crow/crow.hxx>
#include <mutex>
#include <engine/analysis/analysis.hxx>


#define GET_ROUTE(name) Routes::route_##name();

namespace Crow
{
class Routes
{
  public:
    Routes(Crow &);
    ~Routes();

    void routes_create();

  private:
    Crow &m_crow;
    Context m_context;

    Analysis::Scan m_scan;
    std::mutex m_mtx;

    void route_search();
    void route_scan();
    void route_def_close_connection(crow::websocket::connection *,
                                    const std::string&);
    void route_def_open_connection(crow::websocket::connection *);
    bool route_def_onaccept_connection(const crow::request *);
    void route_init_analysis();
};
} // namespace Crow