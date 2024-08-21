#pragma once

#include "toml.hxx"

#include <crow.h>
#include <unordered_set>
#include <list>

namespace Crow
{
class Context
{
  public:
    Context(Parser::Toml &);
    ~Context();
    
    /**
     * @brief used in onaccept to check if ip is whitelisted     
     * @details  if ip listed, return true else false
     * @return true 
     * @return false 
     */
    const bool conn_check_whitelist(const crow::request *);
    const void conn_add(crow::websocket::connection *);
    const void conn_erase(crow::websocket::connection *);
    const std::size_t conn_size() const;
    const void conn_send_msg(crow::websocket::connection *,
                             const std::string) const;

    /**
     * @brief return what ip connect
     * 
     * @return const std::string
     * @return nullptr
     */
    const std::string conn_get_remote_ip(crow::websocket::connection *) const;

  private:
    std::unordered_set<crow::websocket::connection *> m_conn;
    Parser::Toml &m_config;
    toml::array m_whitelist;
};
} // namespace Crow