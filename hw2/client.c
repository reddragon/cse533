#include <stdio.h>
#include "utils.h"

int main(int argc, char **argv) {
  assert(argc == 1);
  const char *cargs_file = CARGS_FILE;
  struct client_args *cargs = (struct client_args *)
    malloc(sizeof(struct client_args));
  if (read_cargs(cargs_file, cargs)) {
    exit(1);
  }
  fprintf(stderr, "%s\n", cargs->file_name);
  struct ifi_info *ifi = Get_ifi_info_plus(AF_INET, 0);
  print_ifi_info(ifi);
  return 0;
}
