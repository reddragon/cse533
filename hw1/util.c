#include "util.h"

char *
get_err_str(char *s) {
  char *str = (char *) malloc(sizeof(char) * MAXMSGLEN);
  sprintf(str, "%s. errno: %d (%s)\n", s, errno, ((errno ? strerror(errno) : "")));
  return str;
}

void 
err_sys(char *str) {
  fprintf(stderr, "%s", get_err_str(str));
  exit(1);
}

// A hacky way to check if a string is an ip-address
BOOL 
is_ip_address(char *str) {
  int a[4], ret, i;
  ret = sscanf(str, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]);
  if (ret == 4) {
    for (i = 0; i < 4; i++) {
      if (!(a[i] >= 0 && a[i] <= 0xFF)) {
        return FALSE;
      }
    }
  } else {
    return FALSE;
  }
  return TRUE;
}

UINT
min(UINT a, UINT b) {
  return (a>b)?b:a;
}

UINT
max(UINT a, UINT b) {
  return (a>b)?a:b;
}

void
read_into_buf(struct client_info *cli, UINT max_len) {
  if (cli->read_buf == NULL) {
    cli->read_buf = (char *) malloc(sizeof(char) * max_len);
  }

  cli->read_ptr = 0;
  // Read upto maxlen bytes in buf
  do {
    // printf("Trying to read from sockfd %d, cli->read_buf: %p, max_len: %d\n", cli->sockfd, cli->read_buf, max_len);
    if ((cli->buf_len = read(cli->sockfd, cli->read_buf, max_len)) < 0) {
      if (errno == EINTR) {
        fprintf(stderr, "Got an EINTR, retrying the read\n");
        continue;
      }
      return;
    } else if (cli->buf_len == 0) {
      fprintf(stderr, "Read a 0 byte string\n");
    }
  } while(FALSE);  
}

int
buffered_readline(struct client_info *cli, char *target_buf, UINT len) {
  // If the buffer is exhausted, read more
  if (cli->read_buf == NULL || cli->buf_len == 0 || cli->read_ptr >= cli->buf_len) {
    read_into_buf(cli, min(len, MAXLEN - 1));
    if (cli->buf_len <= 0) {
      fprintf(stderr, "read_into_buf returned %d\n", cli->buf_len);
      return cli->buf_len;
    }
  }

  UINT from = cli->read_ptr, to = from;
  for (; to + 1 < cli->buf_len && cli->read_buf[to] != '\n'; to++);

  memcpy(target_buf, cli->read_buf + from, to - from + 1);
  target_buf[to - from + 1] = 0;
  cli->read_ptr = to + 1;
  return to - from + 1;
}
