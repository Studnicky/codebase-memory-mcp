/*
 * build_version.h — Process-wide build version string.
 *
 * main sets this once at startup from CBM_VERSION; every module that reports
 * or compares the running build (cli version output, mcp server info, the
 * host update-check path) reads it back through this accessor.
 */
#ifndef CBM_BUILD_VERSION_H
#define CBM_BUILD_VERSION_H

/* Set the process-wide build version string. NULL is ignored (retains the
 * previous value, "dev" by default). The string is not copied — pass a
 * pointer with process lifetime (a literal or CBM_VERSION). */
void cbm_build_version_set(const char *ver);

/* Get the process-wide build version string. Never NULL. */
const char *cbm_build_version_get(void);

#endif /* CBM_BUILD_VERSION_H */
