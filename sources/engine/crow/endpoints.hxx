#pragma once

#include <engine/version.hxx>

namespace Crow
{

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define VERSION_PREFIX "/v" TOSTRING(ENGINE_VERSION_MAJOR)
#define API_PREFIX VERSION_PREFIX "/engine"
#define DEFINE_ROUTE(name, path)                                               \
    static constexpr char ROUTE_##name[] = API_PREFIX path;

namespace Endpoints
{
DEFINE_ROUTE(SEARCH, "/search")
DEFINE_ROUTE(SCAN, "/scan")
DEFINE_ROUTE(METADATA, "/metadata")
} // namespace Endpoints
} // namespace Crow