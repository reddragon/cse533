#include "util.h"

char *
resolve_name_to_ip_address(char *name) {
	struct addrinfo *res, hints;
	const char *serv = "http";
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int ret;
	if ((ret = getaddrinfo(name, serv, &hints, &res)) != 0) {
		fprintf(stderr, "Error: %s", gai_strerror(ret));
		exit(1);
	}
	
	char *ip_addr = NULL;
	struct sockaddr *sa;
	struct sockaddr_in *si;
	while (res->ai_next != NULL) {
		sa = res->ai_addr;
		if (sa->sa_family == AF_INET) {
			si = (struct sockaddr_in *)sa;
			ip_addr = (char *)inet_ntoa(si->sin_addr);
			break;
		} else {
			// Not an IPv4 / IPv6 address
		}
		res = res->ai_next;
	}

	if (ip_addr == NULL) {
		char err_str[1000];
		sprintf(err_str, "Could not find an IP Address corresponding to host %s", name);
		err_sys(err_str);
	}

	printf("Found an IP Address %s corresponding to the host %s\n", ip_addr, name);
	return ip_addr;
}

void 
resolve_ip_address_to_name(const char *ip_addr) {
	struct sockaddr_in si;
	// Store IP address in SI format
	inet_aton(ip_addr, &si.sin_addr);

	/* 
	 * struct sockaddr and sockaddr_in are intercastable
	 * http://www.beej.us/guide/bgnet/output/html/multipage/sockaddr_inman.html
	 */
	struct sockaddr *sa = (struct sockaddr *) &si;
	sa->sa_family = AF_INET;
	char name[300], srv[300];
	
	int ret = getnameinfo(sa, sizeof(struct sockaddr), name, sizeof(name), srv, sizeof(srv), 0);
	if (ret) {
		err_sys((char *)gai_strerror(ret));
	}

	printf("The IP Address %s corresponds to host %s\n", ip_addr, name);
}

void 
print_usage(void) {
	fprintf(stderr, "Usage: ./client [Host Name | IP Address]\n");
}

void 
echo(char *ip_addr) {
#define PIPE_BUF_SZ 1024
	pid_t pid;
	char pipe_buf[PIPE_BUF_SZ];
	int pfd[2];
	pipe(pfd);

	pid = fork();
	if (pid == -1) {
		err_sys("Error in fork()");
	}
	else if (pid == 0) {
		// Child closes its read end
		close(pfd[READ_PIPE_FD]);
		/*
		int i;
		printf("In child\n");
		for (i = 0; i < 10; i++) {
			char str[300];
			sprintf(str, "Hello ");
			write(pfd[WRITE_PIPE_FD], str, strlen(str));
			//printf("Written in child\n");
		} */ 
		execlp("xterm", "xterm", "-e", "./echocli", ip_addr, (char *) 0);
		close(pfd[WRITE_PIPE_FD]);
		exit(0);
	} else {
		// Parent closes its write end	
		close(pfd[WRITE_PIPE_FD]);
		int bytes_read = 0;
		while ((bytes_read = read(pfd[READ_PIPE_FD], pipe_buf, PIPE_BUF_SZ)	) != 0) {
			printf("Read: %s\n", pipe_buf);
		}
		close(pfd[READ_PIPE_FD]);
	}
}

int 
main (int argc, char **argv) {
	if (argc != 2) {
		print_usage();
		exit(1);
	}
	
	char *ip_addr;
	if (is_ip_address(argv[1])) {
		ip_addr = argv[1];
		resolve_ip_address_to_name(ip_addr);
	} else {
		ip_addr = resolve_name_to_ip_address(argv[1]);
	}
	
	char str[300];
	printf("Use the 'echo', 'time', or 'quit' commands\n");
	while (TRUE) {
		printf("> ");
		int ret = scanf("%s", str);
		if (ret == 0 || ret == EOF || !strcmp("quit", str)) {
			printf("%sGoodbye!\n", (ret == 0 || ret == EOF ? "\n" : ""));
			break;
		} else if (!strcmp("echo", str)) {
			echo(ip_addr);
			printf("\n");
		} else if (!strcmp("time", str)) {
			printf("executing time command\n");
		} else {
			fprintf(stderr, "Available commands are 'echo', 'time' and 'quit' (without quotes)\n");
		}
	}
	
	return 0;
}

