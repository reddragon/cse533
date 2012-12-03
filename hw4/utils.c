#include "utils.h"

char *
create_tmp_file(void) {
  int r, fd;
  char *file_name;
  r = mkdir("/tmp/dynamic_duo/", 0755);
  assert(r == 0 || (r == -1 && errno == EEXIST));
  file_name = NMALLOC(char, 64);
  strcpy(file_name, "/tmp/dynamic_duo/dsockXXXXXX");
  fd = mkstemp(file_name);
  assert(fd > 0);
  return file_name;
}

