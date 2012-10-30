#ifndef EMAIL_H
#define EMAIL_H

#include <stdio.h>

void send_email(const char *to, const char *cc,
		const char *subject,
		const char *body);

#endif // EMAIL_H
