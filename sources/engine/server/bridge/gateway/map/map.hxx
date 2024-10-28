#pragma once

#include <engine/version.hxx>
#include <functional>
#include <map>
#include <string>
#include <vector>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define VERSION_PREFIX "/v" TOSTRING(ENGINE_VERSION_MAJOR)
#define API_PREFIX VERSION_PREFIX "/engine"

namespace engine
{
    namespace server
    {
        namespace bridge
        {
            namespace gateway
            {
                class Map
                {
                  public:
                    Map(const std::string &);
                    ~Map();

                    void add_route(const std::string &,
                                   const std::function<void()> &);
                    void get_routes(
                        const std::function<void(const std::string)> &);
                    void call_route(const std::string &);
                    [[nodiscard]] const std::string get_base() const;

                  private:
                    const std::string m_base;
                    std::map<std::string, std::function<void()>> m_routes;
                };
            } // namespace gateway
        } // namespace bridge
    } // namespace server
} // namespace engine