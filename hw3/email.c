#include "email.h"
#include <stdio.h>
#include <string.h>

void send_email(const char *to, const char *cc,
		const char *subject,
		const char *body) {
  char cmd[4096];
  sprintf(cmd, "/usr/ucb/Mail -s '%s' -c '%s' %s",
	  subject, cc, to);
  FILE *pf = popen(cmd, "w");
  if (pf) {
    fwrite(body, 1, strlen(body), pf);
    fclose(pf);
  }
}
