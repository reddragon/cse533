// -*- tab-width: 2; c-basic-offset: 2 -*-
#include "utils.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include "myassert.h"

char *create_tmp_file(void) {
  int r, fd;
  char *file_name;
  r = mkdir("/tmp/dynamic_duo/", 0755);
  ASSERT(r == 0 || (r == -1 && errno == EEXIST));
  file_name = NMALLOC(char, 64);
  strcpy(file_name, "/tmp/dynamic_duo/dsockXXXXXX");
  fd = mkstemp(file_name);
  assert(fd > 0);
  return file_name;
}

void *my_malloc(size_t size) {
    // assert(size < 2 * 1048676); // 2MiB
    void *ptr = calloc(1, size);
    ASSERT(ptr);
    return ptr;
}
