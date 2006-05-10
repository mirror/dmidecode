/*
 * Configuration
 */

#ifndef CONFIG_H
#define CONFIG_H

/* Default memory device file */
#ifdef __BEOS__
#define DEFAULT_MEM_DEV "/dev/misc/mem"
#else
#define DEFAULT_MEM_DEV "/dev/mem"
#endif

/* Use mmap or not */
#ifndef __BEOS__
#define USE_MMAP
#endif

/* Use memory alignment workaround or not */
#ifdef __ia64__
#define ALIGNMENT_WORKAROUND
#endif

#endif
