#pragma once

#include <spdlog/spdlog.h>

// clang-format off
#define CONSOLE_INFO(...) spdlog::info(fmt::format(__VA_ARGS__))
#define CONSOLE_ERROR(...) spdlog::error(fmt::format(__VA_ARGS__))
// clang-format on