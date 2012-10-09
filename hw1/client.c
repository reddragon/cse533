#include "util.h"

void
sigchld_handler(int signo) {
	pid_t pid;
	int stat;

	while ((pid = waitpid(-1, &stat, WNOHANG)) > 0) {
		fprintf(stderr, "Signal Handler: Child %d terminated", pid);
		return;
	}
}

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
execute_childproc(char *childproc, char *ip_addr) {
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
		close(pfd[READ_PIPE_FD]);
		char str[100];
		sprintf(str, "%d", pfd[WRITE_PIPE_FD]);
		execlp("xterm", "xterm", "-e", childproc, ip_addr, str, (char *) 0);
		exit(1);
	} else {
		close(pfd[WRITE_PIPE_FD]);
    char buf[MAXMSGLEN];
		int rb = 0;
		while((rb = read(pfd[READ_PIPE_FD], buf, MAXMSGLEN)) > 0) {
			if (rb == 0) continue;
			buf[rb] = 0;
			printf("Child Process: %s\n", buf);
		}
    close(pfd[READ_PIPE_FD]);
		fprintf(stderr, "Child process might have been terminated\n");
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
	
	signal(SIGCHLD, sigchld_handler);
	char str[300];
	printf("Use the 'echo', 'time', or 'quit' commands\n");
	while (TRUE) {
		printf("\n> ");
		int ret = scanf("%s", str);
		if (ret == 0 || ret == EOF || !strcmp("quit", str)) {
			printf("%sGoodbye!\n", (ret == 0 || ret == EOF ? "\n" : ""));
			break;
		} else if (!strcmp("echo", str)) {
			execute_childproc("./echocli", ip_addr);
			printf("\n");
		} else if (!strcmp("time", str)) {
			execute_childproc("./timecli", ip_addr);
		} else {
			fprintf(stderr, "Available commands are 'echo', 'time' and 'quit' (without quotes)\n");
		}
	}
	
	return 0;
}

