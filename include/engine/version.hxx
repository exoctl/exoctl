#pragma once

enum {
    ENGINE_VERSION_CODE = 65536
};
#define ENGINE_VERSION(a, b, c)                                                \
    (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
enum {
    ENGINE_VERSION_MAJOR = 1,
    ENGINE_VERSION_PATCHLEVEL = 0,
    ENGINE_VERSION_SUBLEVEL =
};
0