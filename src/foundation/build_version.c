/*
 * build_version.c — see build_version.h.
 */
#include "foundation/build_version.h"

static const char *g_build_version = "dev";

void cbm_build_version_set(const char *ver) {
    if (ver) {
        g_build_version = ver;
    }
}

const char *cbm_build_version_get(void) {
    return g_build_version;
}
