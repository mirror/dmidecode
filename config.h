/*
 * Configuration
 */

/* Default memory device file */
#ifdef __BEOS__
#define DEFAULT_MEM_DEV "/dev/misc/mem"
#else
#define DEFAULT_MEM_DEV "/dev/mem"
#endif

/* Use mmap or not */
#ifdef __linux__
#define USE_MMAP
#endif
