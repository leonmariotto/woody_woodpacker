#include "elftool.h"
#include "elftool_parse.h"
#include "elftool_write.h"
#include "stdio.h"
#include <arpa/inet.h>
#include <byteswap.h>
#include <elf.h>
#include <endian.h>
#include <string.h>

#define STBLOCKS_UNIT 512

int elftool_load(elftool_t *bin, char *bin_path) {
  struct stat stats;
  int fd;
  int r = 0;

  if (!bin || !bin_path)
      return EINVAL;
  bin->path = strdup(bin_path);
  if ((fd = open(bin_path, O_RDONLY)) <= 0) {
    r = EINVAL;
    fprintf(stderr, "open failed");
  }
  if (r == 0) {
    if (fstat(fd, &stats)) {
      r = EINVAL;
      fprintf(stderr, "fstat failed");
    }
  }
  if (r == 0) {
    if ((stats.st_mode & S_IFMT) != S_IFREG) {
      r = EINVAL;
      fprintf(stderr, "This is not a regular file, abort");
    }
  }
  if (r == 0) {
    bin->length = stats.st_blocks * STBLOCKS_UNIT;
    if (bin->length % 4096) {
      r = EINVAL;
      fprintf(stderr, "bin->length not aligned to pagesize");
    }
  }
  if (r == 0) {
    if (!(bin->mem = mmap(NULL, bin->length, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE, fd, 0))) {
      r = EINVAL;
      fprintf(stderr, "mmap call failed");
    }
  }
  if (fd >= 0) {
    close(fd);
  }
  return (r);
}

