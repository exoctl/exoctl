#pragma once

#include <engine/version.hxx>
#include <string>
#include <utility>

// Helper macros for stringification
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Version and base API prefixes
#define VERSION_PREFIX "/v" TOSTRING(ENGINE_VERSION_MAJOR)
#define API_PREFIX VERSION_PREFIX "/engine"

// Helper function to concatenate multiple paths
template <typename... Args>
std::string concatenate_paths(const std::string &p_base, Args &&...p_args)
{
    std::string result = p_base;
    ((result.append(p_args)),
     ...); // Fold expression to concatenate all arguments
    return result;
} // namespace std::string

// Macro to define routes with variable prefixes
#define DEFINE_ROUTE(name, ...)                                                \
    static const std::string ROUTE_##name =                                    \
        concatenate_paths(API_PREFIX, __VA_ARGS__);

namespace Crow
{
namespace Endpoints
{
DEFINE_ROUTE(ENDPOINTS, "/endpoints")

// Analysis endpoints
DEFINE_ROUTE(SEARCH_YARA, "/analysis", "/search_yara")
DEFINE_ROUTE(SCAN_SIG_PACKED, "/analysis", "/scan_sig_packed")
DEFINE_ROUTE(SCAN_YARA, "/analysis", "/scan_yara")
DEFINE_ROUTE(SCAN_YARA_REPORTS, "/analysis", "/scan_yara", "/reports")

// Data endpoints
DEFINE_ROUTE(METADATA, "/data", "/metadata")

// Rev endpoints
DEFINE_ROUTE(
    CAPSTONE_DISASS_X86_64, "/rev", "/capstone", "/disassembly", "/x86_64")
DEFINE_ROUTE(
    CAPSTONE_DISASS_ARM64, "/rev", "/capstone", "/disassembly", "/arm64")
} // namespace Endpoints
} // namespace Crow