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
// analysis endpoint 
DEFINE_ROUTE(SEARCH_YARA, "/analysis/search_yara")
DEFINE_ROUTE(SCAN_YARA, "/analysis/scan_yara")
// metadada endpoint
DEFINE_ROUTE(METADATA, "/parser/metadata")
} // namespace Endpoints
} // namespace Crow