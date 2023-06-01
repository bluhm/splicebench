/*
 * Copyright (c) 2023 Alexander Bluhm <bluhm@genua.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int family = AF_UNSPEC;
int splicemode;
char *listenhost, *bindouthost, *connecthost;
char *listenport, *bindoutport, *connectport;

struct ev_splice {
	struct	event ev;
	int	sock;
};

void	socket_listen(void);
void	accepting_cb(int, short, void *);
void	connected_cb(int, short, void *);
void	socket_splice(struct ev_splice *, int, int);
void	unsplice_cb(int, short, void *);
void	process_copy(struct ev_splice *, int, int);
void	waitpid_cb(int, short, void *);
int	socket_connect(const char *, const char *, const char *, const char *,
	    struct addrinfo *);
int	socket_bind_connect(struct addrinfo *, const char *,
	    const char *, struct addrinfo *, const char **);
int	socket_bind(const char *, const char *, struct addrinfo *);
void	address_parse(const char *, char **, char **);

static void
usage(void)
{
	fprintf(stderr, "usage: splicebench [-46] copy | splice "
	    "[listen] [bindout] connect\n"
	    "    -4     listen on IPv4\n"
	    "    -6     listen on IPv6\n"
	    );
	exit(2);
}

int
main(int argc, char *argv[])
{
	int ch;

	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(1, "setvbuf");

	while ((ch = getopt(argc, argv, "46")) != -1) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		errx(1, "copy or splice required");
	if (strcmp(argv[0], "copy") == 0) {
		splicemode = 0;
		setprogname("splicebench copy");
	} else if (strcmp(argv[0], "splice") == 0) {
#ifdef __OpenBSD__
		splicemode = 1;
		setprogname("splicebench splice");
#else
		errx(1, "splice mode only supported on OpenBSD");
#endif
	} else
		errx(1, "bad copy or splice: %s", argv[0]);

	listenhost = bindouthost = connecthost = NULL;
	listenport = bindoutport = connectport = NULL;
	switch (argc) {
	case 2:
		address_parse(argv[1], &connecthost, &connectport);
		break;
	case 3:
		address_parse(argv[1], &listenhost, &listenport);
		address_parse(argv[2], &connecthost, &connectport);
		break;
	case 4:
		address_parse(argv[1], &listenhost, &listenport);
		address_parse(argv[2], &bindouthost, &bindoutport);
		address_parse(argv[3], &connecthost, &connectport);
		break;
	default:
		usage();
	}
	if (listenport == NULL)
		listenport = "12345";
	if (connectport == NULL)
		connectport = "12345";

	event_init();

	socket_listen();

	event_dispatch();

	return 0;
}

void
socket_listen(void)
{
	struct addrinfo hints;
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	struct sockaddr_storage ss;
	socklen_t sslen;
	sslen = sizeof(ss);
	int lsock, error;
	struct event *ev;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;

	lsock = socket_bind(listenhost, listenport, &hints);

	sslen = sizeof(ss);
	if (getsockname(lsock, (struct sockaddr *)&ss, &sslen) == -1)
		err(1, "getsockname listen");
	error = getnameinfo((struct sockaddr *)&ss, sslen, host, sizeof(host),
	    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));
	printf("listen name: %s %s\n", host, serv);

	if (listen(lsock, 1) < 0)
		err(1, "listen");

	if ((ev = malloc(sizeof(*ev))) == NULL)
		err(1, "malloc ev listen");

	event_set(ev, lsock, EV_READ, accepting_cb, NULL);
	event_add(ev, NULL);
}

void
accepting_cb(int lsock, short event, void *arg)
{
	struct addrinfo hints;
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	struct sockaddr_storage ss;
	socklen_t sslen;
	int asock, csock, error;
	struct ev_splice *evs;

	sslen = sizeof(ss);
	asock = accept(lsock, (struct sockaddr *)&ss, &sslen);
	if (asock < 0)
		err(1, "accept");
	error = getnameinfo((struct sockaddr *)&ss, sslen, host, sizeof(host),
	    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));
	printf("accept peer: %s %s\n", host, serv);

	sslen = sizeof(ss);
	if (getsockname(asock, (struct sockaddr *)&ss, &sslen) == -1)
		err(1, "getsockname accept");
	error = getnameinfo((struct sockaddr *)&ss, sslen, host, sizeof(host),
	    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));
	printf("accept name: %s %s\n", host, serv);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	csock = socket_connect(connecthost, connectport,
	    bindouthost, bindoutport, &hints);

	if ((evs = malloc(sizeof(*evs))) == NULL)
		err(1, "malloc ev connect");

	event_set(&evs->ev, csock, EV_WRITE, connected_cb, evs);
	evs->sock = asock;
	event_add(&evs->ev, NULL);
}

void
connected_cb(int csock, short event, void *arg)
{
	struct ev_splice *evs = arg;
	int asock = evs->sock;
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	struct sockaddr_storage ss;
	socklen_t sslen;
	int error;

	sslen = sizeof(ss);
	if (getsockname(csock, (struct sockaddr *)&ss, &sslen) == -1)
		err(1, "getsockname connect");
	error = getnameinfo((struct sockaddr *)&ss, sslen, host, sizeof(host),
	    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));
	printf("connect name: %s %s\n", host, serv);

	sslen = sizeof(ss);
	if (getpeername(csock, (struct sockaddr *)&ss, &sslen) == -1)
		err(1, "getpeername connect");
	error = getnameinfo((struct sockaddr *)&ss, sslen, host, sizeof(host),
	    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));
	printf("connect peer: %s %s\n", host, serv);

#ifdef __OpenBSD__
	if (splicemode)
		socket_splice(evs, asock, csock);
	else
#endif
		process_copy(evs, asock, csock);
}

#ifdef __OpenBSD__
void
socket_splice(struct ev_splice *evs, int from, int to)
{
	if (setsockopt(from, SOL_SOCKET, SO_SPLICE, &to, sizeof(int)) < 0)
		err(1, "setsockopt SO_SPLICE");

	event_set(&evs->ev, from, EV_READ, unsplice_cb, evs);
	evs->sock = to;
	event_add(&evs->ev, NULL);
}

void
unsplice_cb(int from, short event, void *arg)
{
	struct ev_splice *evs = arg;
	int to = evs->sock;
	socklen_t len;
	int error;

	len = sizeof(int);
	if (getsockopt(from, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
		err(1, "getsockopt SO_ERROR");
	if (error) {
		errno = error;
		err(1, "splice");
	}

	close(from);
	close(to);
	free(evs);
}
#endif

void
process_copy(struct ev_splice *evs, int from, int to)
{
	int pfds[2];
	pid_t child;

	if (pipe(pfds) < 0)
		err(1, "pipe");
	if (fflush(stdout) != 0)
		err(1, "fflush");

	/* fork a process so that multiple streams copy in parallel */
	child = fork();
	if (child < 0)
		err(1, "fork");

	if (child == 0) {
		/* child */
		char *buf;

		if (close(pfds[0]))
			err(1, "close");
		if ((buf = malloc(10*1024*1024)) == NULL)
			err(1, "malloc copy buf");
		for (;;) {
			ssize_t in, out;

			in = read(from, buf, 10*1024*1024);
			if (in < 0)
				err(1, "read");
			if (in == 0)
				break;
			out = write(to, buf, in);
			if (out < 0)
				err(1, "write");
			if (out != in)
				errx(1, "partial write %zd of %zd", out, in);
		}
		_exit(0);
	}

	/* parent */
	if (close(pfds[1]))
		err(1, "close");
	close(from);
	close(to);

	event_set(&evs->ev, pfds[0], EV_READ, waitpid_cb, evs);
	evs->sock = child;
	event_add(&evs->ev, NULL);
}

void
waitpid_cb(int pfd, short event, void *arg)
{
	struct ev_splice *evs = arg;
	pid_t child = evs->sock;
	int status;

	if (waitpid(child, &status, 0))
		err(1, "waitpid");
	if (status != 0)
		errx(1, "copy child: %d", status);

	close(pfd);
	free(evs);
}

int
socket_connect(const char *host, const char *service,
    const char *bindhost, const char *bindservice,
    struct addrinfo *hints)
{
	struct addrinfo *res, *res0;
	int error, sock;
	int save_errno;
	const char *cause = NULL;

	error = getaddrinfo(host, service, hints, &res0);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));
	sock = -1;
	for (res = res0; res; res = res->ai_next) {
		if (bindhost == NULL && bindservice == NULL) {
			sock = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol);
			if (sock < 0) {
				cause = "socket";
				continue;
			}
			if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
				cause = "connect";
				save_errno = errno;
				close(sock);
				errno = save_errno;
				sock = -1;
				continue;
			}
		} else {
			sock = socket_bind_connect(res, bindhost, bindservice,
			    hints, &cause);
			if (sock < 0)
				continue;
		}
		break;  /* okay we got one */
	}
	if (sock < 0) {
		err(1, "%s '%s%s%s%s%s%s%s'", cause,
		    bindhost ? bindhost : "",
		    (bindhost && bindservice) ? "' '" : "",
		    bindservice ? bindservice : "",
		    (bindhost || bindservice) ? "' '" : "",
		    host ? host : "",
		    (host && service) ? "' '" : "",
		    service ? service : "");
	}
	hints->ai_family = res->ai_family;
	freeaddrinfo(res0);
	return sock;
}

int
socket_bind_connect(struct addrinfo *res, const char *host,
    const char *service, struct addrinfo *hints, const char **cause)
{
	struct addrinfo *bindres, *bindres0;
	int error, sock;
	int save_errno;

	hints->ai_family = res->ai_family;
	hints->ai_socktype = res->ai_socktype;
	hints->ai_protocol = res->ai_protocol;
	error = getaddrinfo(host, service, hints, &bindres0);
	if (error) {
		errx(1, "getaddrinfo '%s%s%s': %s", host ? host : "",
		    (host && service) ? "' '" : "", service ? service : "",
		    gai_strerror(error));
	}
	sock = -1;
	for (bindres = bindres0; bindres; bindres = bindres->ai_next) {
		sock = socket(bindres->ai_family, bindres->ai_socktype,
		    bindres->ai_protocol);
		if (sock < 0) {
			*cause = "socket";
			continue;
		}
		if (bind(sock, bindres->ai_addr, bindres->ai_addrlen) < 0) {
			*cause = "bind";
			save_errno = errno;
			close(sock);
			errno = save_errno;
			sock = -1;
			continue;
		}
		if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
			*cause = "connect";
			save_errno = errno;
			close(sock);
			errno = save_errno;
			sock = -1;
			continue;
		}
		break;  /* okay we got one */
	}
	freeaddrinfo(bindres0);
	return sock;
}

int
socket_bind(const char *host, const char *service, struct addrinfo *hints)
{
	struct addrinfo *res, *res0;
	int error, sock;
	int save_errno;
	const char *cause = NULL;

	error = getaddrinfo(host, service, hints, &res0);
	if (error) {
		errx(1, "getaddrinfo '%s%s%s': %s", host ? host : "",
		    (host && service) ? "' '" : "", service ? service : "",
		    gai_strerror(error));
	}
	sock = -1;
	for (res = res0; res; res = res->ai_next) {
		int optval;

		sock = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (sock < 0) {
			cause = "socket";
			continue;
		}
		optval = 1;
		if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval,
		    sizeof(optval)) == -1)
			err(1, "setsockopt reuseaddr");
		if (bind(sock, res->ai_addr, res->ai_addrlen) < 0) {
			cause = "bind";
			save_errno = errno;
			close(sock);
			errno = save_errno;
			sock = -1;
			continue;
		}
		break;  /* okay we got one */
	}
	if (sock < 0) {
		err(1, "%s '%s%s%s'", cause, host ? host : "",
		    (host && service) ? "' '" : "", service ? service : "");
	}
	hints->ai_family = res->ai_family;
	freeaddrinfo(res0);
	return sock;
}

void
address_parse(const char *address, char **host, char **port)
{
	char *str;

	if ((str = strdup(address)) == NULL)
		err(1, "address '%s'", address);

	*host = str;
	if (**host == '[') {
		*(*host)++ = '\0';
		str = strchr(*host, ']');
		if (str == NULL)
			errx(1, "address '%s': missing ]", address);
		*str++ = '\0';
	}
	*port = strrchr(str, ':');
	if (*port != NULL)
		*(*port)++ = '\0';
	if (**host == '\0')
		*host = NULL;
}
