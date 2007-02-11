#include <sys/types.h>

#include "types.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

int checksum(const u8 *buf, size_t len);
void *mem_chunk(size_t base, size_t len, const char *devmem);
