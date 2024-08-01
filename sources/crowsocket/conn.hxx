#pragma once

#include <crow.h>
#include <map>

namespace Connection
{
    class Context
    {
    public:
        Context();
        ~Context();

        const void add_conn(crow::websocket::connection &);
        const void send_msg(const std::string, const std::string);
        const void remove_all_conn();
        const void remove_conn(crow::websocket::connection &);

    private:
        std::map<const std::string, crow::websocket::connection&> m_conn;
    };
}