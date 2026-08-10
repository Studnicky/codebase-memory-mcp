#ifndef TEST_DAEMON_RUNTIME_CONTRACT_H
#define TEST_DAEMON_RUNTIME_CONTRACT_H

/* The parent watchdog covers both the activation exchange and its bounded
 * close. Process bootstrap uses posix_spawn and does not duplicate the
 * sanitizer-heavy parent address space. */
#define TF_RUNTIME_IMAGE_EXCHANGE_TIMEOUT_MS 60000U
#define TF_RUNTIME_IMAGE_WATCHDOG_MS \
    (2U * TF_RUNTIME_IMAGE_EXCHANGE_TIMEOUT_MS + 5000U)
#define TF_RUNTIME_IMAGE_WATCHDOG_SECONDS ((TF_RUNTIME_IMAGE_WATCHDOG_MS + 999U) / 1000U)

#endif /* TEST_DAEMON_RUNTIME_CONTRACT_H */
