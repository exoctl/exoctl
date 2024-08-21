#pragma once

#include "conn.hxx"
#include "crow.hxx"

#include <mutex>

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
    std::mutex m_mtx;

    void route_search();
    void route_scan();
    void route_def_close_connection(crow::websocket::connection *,
                                    const std::string&);
    void route_def_open_connection(crow::websocket::connection *);
    bool route_def_onaccept_connection(const crow::request *);
};
} // namespace Crow