#include <engine/server/bridge/gateway/map/map.hxx>

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            namespace gateway
            {
                Map::Map(const std::string &p_base) : m_base(p_base)
                {
                }

                void Map::add_route(const std::string &p_route,
                                    const std::function<void()> &p_handle)
                {
                    const std::string full_route = m_base + p_route;
                    m_routes[full_route] = p_handle;
                }

                void Map::get_routes(
                    const std::function<void(const std::string)> &p_handle)
                {
                    for (const auto &entry : m_routes) {
                        p_handle(entry.first);
                    }
                }

                void Map::call_route(const std::string &p_route)
                {
                    auto it = m_routes.find(p_route);
                    if (it != m_routes.end())
                        it->second();
                }

                const std::string Map::get_base() const
                {
                    return m_base;
                }
            } // namespace gateway
        } // namespace bridge
    } // namespace server
} // namespace engine