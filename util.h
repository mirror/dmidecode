#include <sys/types.h>

#include "types.h"

int myread(int fd, u8 *buf, size_t count, const char *prefix);
int checksum(const u8 *buf, size_t len);
void *mem_chunk(off_t base, off_t len, const char *devmem);
