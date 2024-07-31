#include "routes.hxx"
#include "rnames.hxx"
#include "iscan.hxx"
#include "scan.hxx"

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
        CROW_WEBSOCKET_ROUTE(m_crow.get_app(), ROUTE_SEARCH)
            .onopen([&](crow::websocket::connection &conn)
                    { ; })
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t)
                     { ; })
            .onmessage([&](crow::websocket::connection & /*conn*/, const std::string &data, bool is_binary)
                       {
                if (is_binary)
                    ;
                else
                    ; });
    }

    void Routes::route_scan()
    {
        Analysis::Scan *Scan = new Analysis::Scan();

        SCAN(Scan, yara, "test");

        CROW_WEBSOCKET_ROUTE(m_crow.get_app(), ROUTE_SCAN)
            .onopen([&](crow::websocket::connection &conn)
                    {  })
            .onclose([&](crow::websocket::connection &conn, const std::string &reason, uint16_t)
                     { ; })
            .onmessage([&](crow::websocket::connection & /*conn*/, const std::string &data, bool is_binary)
                       {
                if (is_binary)
                    ;
                else
                    ; });
    }
};