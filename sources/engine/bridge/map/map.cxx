#include <engine/bridge/map/map.hxx>

namespace engine
{
    namespace bridge
    {
        namespace map
        {
            Map::Map(const std::string &p_base) : base_(p_base)
            {
            }

            void Map::add_route(const std::string &p_route,
                                const std::function<void()> &&p_handle)
            {
                const std::string full_route = base_ + p_route;
                routes_[full_route] = p_handle;
            }

            void Map::get_routes(
                const std::function<void(const std::string)> &p_handle)
            {
                for (const auto &entry : routes_) {
                    p_handle(entry.first);
                }
            }

            void Map::call_route(const std::string &p_route)
            {
                auto it = routes_.find(p_route);
                if (it != routes_.end())
                    it->second();
            }

            const std::string Map::get_base() const
            {
                return base_;
            }
        } // namespace map
    } // namespace bridge
} // namespace engine