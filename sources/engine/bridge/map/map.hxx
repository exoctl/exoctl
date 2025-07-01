#pragma once

#include <functional>
#include <map>
#include <string>
#include <vector>

#include <engine/version/version.hxx>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define VERSION_PREFIX "/v" TOSTRING(ENGINE_MAJOR)
#define API_PREFIX(endpoint) VERSION_PREFIX "/engine/" endpoint

namespace engine
{
    namespace bridge
    {
        namespace map
        {
            class Map
            {
              public:
                Map(const std::string &);
                ~Map() = default;

                void add_route(const std::string &,
                               const std::function<void()> &&);
                void get_routes(const std::function<void(const std::string)> &);
                void call_route(const std::string &);
                [[nodiscard]] const std::string get_base() const;

              private:
                const std::string m_base;
                std::map<std::string, std::function<void()>> m_routes;
            };
        } // namespace map
    } // namespace bridge
} // namespace engine