#pragma once

#include <fmt/core.h>

#define LOG_INFO(...) fmt::print("[INFO] {}\n", fmt::format(__VA_ARGS__))
#define LOG_ERROR(...) fmt::print(stderr, "[ERROR] {}\n", fmt::format(__VA_ARGS__))