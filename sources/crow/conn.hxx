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
        const void erase_conn(crow::websocket::connection *);
        const void send_msg(crow::websocket::connection *, const std::string);
        const void remove_all_conn();

    private:
        std::unordered_set<crow::websocket::connection* > m_conn;
    };
}