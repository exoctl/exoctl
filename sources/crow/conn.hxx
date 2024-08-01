#pragma once

#include <crow.h>
#include <unordered_set>

namespace Connection
{
    class Context
    {
    public:
        Context(void);
        ~Context();

        const void add_conn(crow::websocket::connection *);
        const void erase_conn(crow::websocket::connection *, const std::string&);
        const std::size_t size_conn() const;
        const void send_msg_conn(crow::websocket::connection *, const std::string) const;

    private:
        std::unordered_set<crow::websocket::connection* > m_conn;
    };
}