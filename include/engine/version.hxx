#pragma once

#define ENGINE_VERSION_CODE 65536
#define ENGINE_VERSION(a, b, c)                                                \
    (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#define ENGINE_VERSION_MAJOR 1
#define ENGINE_VERSION_PATCHLEVEL 0
#define ENGINE_VERSION_SUBLEVEL 0