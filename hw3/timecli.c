#include "utils.h"
#include "api.h"
#include <string.h>
#include <stdlib.h>

cli_dsock c;

void
test_api(void) {
  msg_send(c.sockfd, "123.456.789.123", 1234, "Hello!", 0);
}

int
main(int argc, char **argv) {
  char *file_name = create_tempfile();
  VERBOSE("Client File Name: %s\n", file_name);
  
  create_cli_dsock(file_name, &c);
  test_api();
  return 0;
}
