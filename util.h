#include <sys/types.h>

#include "types.h"

int checksum(const u8 *buf, size_t len);
void *mem_chunk(size_t base, size_t len, const char *devmem);
