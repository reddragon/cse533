#include "utils.h"
#include "api.h"
#include <string.h>
#include <stdlib.h>

int
main(int argc, char **argv) {
  char *file_name = create_tempfile();
  VERBOSE("Client File Name: %s\n", file_name);
  
  cli_dsock c;
  create_cli_dsock(file_name, &c);
  return 0;
}
