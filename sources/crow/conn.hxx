#pragma once

#include <crow.h>
#include <unordered_set>

namespace Connection
{
    class Context
    {
    public:
        Context();
        ~Context();

        const void conn_add(crow::websocket::connection *);
        const void conn_erase(crow::websocket::connection *, const std::string&);
        const std::size_t conn_size() const;
        const void conn_send_msg(crow::websocket::connection *, const std::string) const;
        
    private:
        std::unordered_set<crow::websocket::connection* > m_conn;
    };
}