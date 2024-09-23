#pragma once

#include <fmt/core.h>

// clang-format off
#define CONSOLE_INFO(...) fmt::print("[INFO] {}\n", fmt::format(__VA_ARGS__))
#define CONSOLE_ERROR(...) fmt::print(stderr, "[ERROR] {}\n", fmt::format(__VA_ARGS__))
// clang-format on