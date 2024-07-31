#include "routes.hxx"
#include "rnames.hxx"

namespace Crow
{
    Routes::Routes(CrowApi &p_crow) : m_crow(p_crow)
    {
    }

    Routes::~Routes()
    {
    }

    void Routes::create_routes()
    {
        GET_ROUTE(search);
        GET_ROUTE(scan);
    }

    void Routes::route_search()
    {
        CROW_ROUTE(m_crow.get_app(), ROUTE_SEARCH)
        ([]()
         { return "crow 200"; });
    }

    void Routes::route_scan()
    {
        CROW_ROUTE(m_crow.get_app(), ROUTE_SCAN)
        ([]()
         { return "crow 200"; });
    }
};