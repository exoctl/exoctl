#pragma once

#include <engine/version.hxx>

namespace Crow
{

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Version and base API prefixes
#define VERSION_PREFIX "/v" TOSTRING(ENGINE_VERSION_MAJOR)
#define API_PREFIX VERSION_PREFIX "/engine"

// Specific module prefixes
#define ANALYSIS_PREFIX API_PREFIX "/analysis"
#define DATA_PREFIX API_PREFIX "/data"
#define REV_PREFIX API_PREFIX "/rev"

// Macro to define routes with module-specific prefixes
#define DEFINE_ROUTE(name, prefix, path)                                       \
    static constexpr char ROUTE_##name[] = prefix path;

namespace Endpoints
{
// Analysis endpoints
DEFINE_ROUTE(SEARCH_YARA, ANALYSIS_PREFIX, "/search_yara")
DEFINE_ROUTE(SCAN_SIG_PACKED, ANALYSIS_PREFIX, "/scan_sig_packed")
DEFINE_ROUTE(SCAN_YARA, ANALYSIS_PREFIX, "/scan_yara")

// Data endpoints
DEFINE_ROUTE(METADATA, DATA_PREFIX, "/metadata")

// Rev endpoints
DEFINE_ROUTE(CAPSTONE_DISASS_X86_64, REV_PREFIX, "/capstone/disassembly/x86_64")
DEFINE_ROUTE(CAPSTONE_DISASS_ARM, REV_PREFIX, "/capstone/disassembly/arm")

} // namespace Endpoints
} // namespace Crow