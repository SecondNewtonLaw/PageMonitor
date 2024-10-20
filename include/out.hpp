#pragma once

#include <cstdio>

#define error(fmt, ...) fprintf(stderr, "[PageMonitor/ERROR] " fmt "\n", __VA_ARGS__)
#define info(fmt, ...) fprintf(stdout, "[PageMonitor/INFO] " fmt "\n", __VA_ARGS__)
#define warn(fmt, ...) fprintf(stdout, "[PageMonitor/WARN] " fmt "\n", __VA_ARGS__)

#ifdef NDEBUG
#    define debug(fmt, ...)
#else
#    define debug(fmt, ...) fprintf(stdout, "vulkan [dbg] " fmt "\n", __VA_ARGS__)
#endif // NDEBUG
