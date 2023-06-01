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

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#define IP_RECVDSTADDR	IP_ORIGDSTADDR
#endif

int family = AF_UNSPEC;
int splicemode, timeout = 1, udpmode;
char *listenhost, *bindouthost, *connecthost;
char *listenport, *bindoutport, *connectport;
uint16_t listensockport;

struct ev_splice {
	struct	event ev;
	int	sock;
};

void	socket_listen(void);
void	accepting_cb(int, short, void *);
void	connected_cb(int, short, void *);
void	receiving_cb(int, short, void *);
void	foreigninfo_print(const char *, int, struct sockaddr_storage *);
void	localinfo_print(const char *, int, struct sockaddr_storage *);
void	nameinfo_print(const char *, const char *, struct sockaddr_storage *,
	    socklen_t);
void	stream_splice(struct ev_splice *, int, int);
void	dgram_splice(struct ev_splice *, int, int);
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
	fprintf(stderr, "usage: splicebench [-46u] [-t timeout] copy | splice "
	    "[listen] [bindout] connect\n"
	    "    -4		listen on IPv4\n"
	    "    -6		listen on IPv6\n"
	    "    -t timeout	timeout fo UDP splice, default 1 second\n"
	    "    -u		splice UDP instead of TCP\n"
	    );
	exit(2);
}

int
main(int argc, char *argv[])
{
	const char *errstr;
	int ch;

	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(1, "setvbuf");

	while ((ch = getopt(argc, argv, "46t:u")) != -1) {
		switch (ch) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 't':
			timeout = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "timeout is %s: %s",
				    errstr, optarg);
			break;
		case 'u':
			udpmode = 1;
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

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		err(1, "signal");

	socket_listen();

	event_dispatch();

	return 0;
}

void
socket_listen(void)
{
	struct addrinfo hints;
	struct sockaddr_storage local;
	int lsock;
	struct event *ev;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	if (udpmode) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;

	lsock = socket_bind(listenhost, listenport, &hints);
	localinfo_print("listen", lsock, &local);
	if (local.ss_family == AF_INET)
		listensockport = ((struct sockaddr_in *)(&local))->sin_port;
	if (local.ss_family == AF_INET6)
		listensockport = ((struct sockaddr_in6 *)(&local))->sin6_port;

	if ((ev = malloc(sizeof(*ev))) == NULL)
		err(1, "malloc ev listen");

	if (udpmode) {
		event_set(ev, lsock, EV_READ, receiving_cb, NULL);
		event_add(ev, NULL);
	} else {
		if (listen(lsock, 1) < 0)
			err(1, "listen");

		event_set(ev, lsock, EV_READ, accepting_cb, NULL);
		event_add(ev, NULL);
	}
}

void
accepting_cb(int lsock, short event, void *arg)
{
	struct addrinfo hints;
	struct sockaddr_storage ss;
	socklen_t sslen;
	int asock, csock;
	struct ev_splice *evs;

	sslen = sizeof(ss);
	asock = accept(lsock, (struct sockaddr *)&ss, &sslen);
	if (asock < 0)
		err(1, "accept");
	nameinfo_print("accept", "peer", &ss, sslen);
	localinfo_print("accept", asock, &ss);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	if (udpmode) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}
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
	struct sockaddr_storage ss;

	localinfo_print("connect", csock, &ss);
	foreigninfo_print("connect", csock, &ss);

#ifdef __OpenBSD__
	if (splicemode)
		stream_splice(evs, asock, csock);
	else
#endif
		process_copy(evs, asock, csock);
}


void
receiving_cb(int lsock, short event, void *arg)
{
	struct addrinfo hints;
	char buf[64*1024];
	struct sockaddr_storage foreign, local;
	socklen_t foreignlen, locallen;
	struct sockaddr_in *sin = NULL;
	struct sockaddr_in6 *sin6 = NULL;
	int asock, csock, optval;
	struct iovec iov[1];
	union {
		struct cmsghdr cmsg;
		unsigned char buf[
		    CMSG_SPACE(sizeof(struct in_addr)) +
		    CMSG_SPACE(sizeof(struct in6_pktinfo)) +
		    CMSG_SPACE(sizeof(uint16_t))];
	} cmsgbuf;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct ev_splice *evs;
	ssize_t in, out;

	memset(iov, 0, sizeof(iov));
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &foreign;
	msg.msg_namelen = sizeof(foreign);
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
	msg.msg_control = &cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	in = recvmsg(lsock, &msg, 0);
	if (in < 0)
		err(1, "recvmsg");
	foreignlen = msg.msg_namelen;

	if (msg.msg_flags & MSG_CTRUNC)
		errx(1, "control message truncated");
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_addr)) &&
		    cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVDSTADDR) {
			sin = (struct sockaddr_in *)&local;
			locallen = sizeof(*sin);
			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
#ifdef __OpenBSD__
			sin->sin_len = sizeof(*sin);
#else
			sin->sin_port = listensockport;
#endif
			sin->sin_addr = *(struct in_addr *)CMSG_DATA(cmsg);
		}
#ifdef __OpenBSD__
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(uint16_t)) &&
		    cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVDSTPORT) {
			sin->sin_port = *(uint16_t *)CMSG_DATA(cmsg);
		}
#endif
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo)) &&
		    cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_PKTINFO) {
			const struct in6_pktinfo *pi6;

			pi6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			sin6 = (struct sockaddr_in6 *)&local;
			locallen = sizeof(*sin6);
			memset(sin6, 0, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
#ifdef __OpenBSD__
			sin6->sin6_len = sizeof(*sin6);
#else
			sin6->sin6_port = listensockport;
#endif
			sin6->sin6_addr = pi6->ipi6_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				sin6->sin6_scope_id = pi6->ipi6_ifindex;
		}
#ifdef __OpenBSD__
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(uint16_t)) &&
		    cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_RECVDSTPORT) {
			sin6->sin6_port = *(uint16_t *)CMSG_DATA(cmsg);
		}
#endif
	}

	nameinfo_print("accept", "peer", &foreign, foreignlen);
	nameinfo_print("accept", "sock", &local, locallen);

	asock = socket(foreign.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (asock < 0)
		err(1, "socket");
	optval = 1;
	if (setsockopt(asock, SOL_SOCKET, SO_REUSEPORT, &optval,
	    sizeof(optval)) == -1)
		err(1, "setsockopt reuseport");
	if (bind(asock, (struct sockaddr *)&local, locallen) < 0)
		err(1, "bind");
	if (connect(asock, (struct sockaddr *)&foreign, foreignlen) < 0)
		err(1, "connect");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	csock = socket_connect(connecthost, connectport,
	    bindouthost, bindoutport, &hints);

	out = send(csock, buf, in, 0);
	if (out < 0)
		err(1, "send");
	if (out != in)
		errx(1, "partial send %zd of %zd", out, in);

	if ((evs = malloc(sizeof(*evs))) == NULL)
		err(1, "malloc ev connect");

#ifdef __OpenBSD__
	if (splicemode)
		dgram_splice(evs, asock, csock);
	else
#endif
		process_copy(evs, asock, csock);
}

void
foreigninfo_print(const char *name, int sock, struct sockaddr_storage *ss)
{
	socklen_t sslen;

	sslen = sizeof(*ss);
	if (getpeername(sock, (struct sockaddr *)ss, &sslen) == -1)
		err(1, "getpeername");
	nameinfo_print(name, "peer", ss, sslen);
}

void
localinfo_print(const char *name, int sock, struct sockaddr_storage *ss)
{
	socklen_t sslen;

	sslen = sizeof(*ss);
	if (getsockname(sock, (struct sockaddr *)ss, &sslen) == -1)
		err(1, "getsockname");
	nameinfo_print(name, "sock", ss, sslen);
}

void
nameinfo_print(const char *name, const char *side, struct sockaddr_storage *ss,
    socklen_t sslen)
{
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	int error;

	error = getnameinfo((struct sockaddr *)ss, sslen, host, sizeof(host),
	    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));
	printf("%s %s: %s %s\n", name, side, host, serv);
}

#ifdef __OpenBSD__
void
stream_splice(struct ev_splice *evs, int from, int to)
{
	if (setsockopt(from, SOL_SOCKET, SO_SPLICE, &to, sizeof(int)) < 0)
		err(1, "setsockopt SO_SPLICE");

	event_set(&evs->ev, from, EV_READ, unsplice_cb, evs);
	evs->sock = to;
	event_add(&evs->ev, NULL);
}

void
dgram_splice(struct ev_splice *evs, int from, int to)
{
	struct splice sp;

	memset(&sp, 0, sizeof(sp));
	sp.sp_fd = to;
	sp.sp_idle.tv_sec = timeout;

	if (setsockopt(from, SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp)) < 0)
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
	off_t splicelen;
	socklen_t len;
	int error;

	len = sizeof(error);
	if (getsockopt(from, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
		err(1, "getsockopt SO_ERROR");
	if (error == ETIMEDOUT)
		error = 0;
	if (error && error != ETIMEDOUT) {
		errno = error;
		err(1, "splice");
	}
	len = sizeof(splicelen);
	if (getsockopt(from, SOL_SOCKET, SO_SPLICE, &splicelen, &len) < 0)
		err(1, "getsockopt SO_SPLICE");
	printf("splice len %lld\n", splicelen);

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

	if (udpmode) {
		struct timeval tv;

		memset(&tv, 0, sizeof(tv));
		tv.tv_sec = timeout;

		if (setsockopt(from, SOL_SOCKET, SO_RCVTIMEO, &tv,
		    sizeof(tv)) < 0)
			err(1, "setsockopt SO_RCVTIMEO");
	}
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
		size_t bufsize = 10*1024*1024;
		off_t copylen = 0;

		if (close(pfds[0]))
			err(1, "close");
		if ((buf = malloc(bufsize)) == NULL)
			err(1, "malloc copy buf");

		for (;;) {
			ssize_t in, out;

			in = recv(from, buf, bufsize, 0);
			if (in < 0 && errno == EWOULDBLOCK)
				in = 0;
			if (in < 0)
				err(1, "read");
			if (in == 0)
				break;
			out = send(to, buf, in, 0);
			if (out < 0)
				err(1, "write");
			if (out != in)
				errx(1, "partial write %zd of %zd", out, in);
			copylen += out;
		}
		printf("copy len %lld\n", (long long)copylen);
		if (fflush(stdout) != 0)
			err(1, "fflush");
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

	if (waitpid(child, &status, 0) < 0)
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
		if (udpmode && res->ai_family == AF_INET) {
			optval = 1;
			if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR,
			    &optval, sizeof(optval)) < 0)
				err(1, "setsockopt IP_RECVDSTADDR");
#ifdef __OpenBSD__
			if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTPORT,
			    &optval, sizeof(optval)) < 0)
				err(1, "setsockopt IP_RECVDSTPORT");
#endif
		}
		if (udpmode && res->ai_family == AF_INET6) {
			optval = 1;
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
			    &optval, sizeof(optval)) < 0)
				err(1, "setsockopt IPV6_RECVDSTPORT");
#ifdef __OpenBSD__
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVDSTPORT,
			    &optval, sizeof(optval)) < 0)
				err(1, "setsockopt IPV6_RECVDSTPORT");
#endif
		}
		optval = 1;
		if (setsockopt(sock, SOL_SOCKET, res->ai_socktype ==
		    SOCK_DGRAM ?  SO_REUSEPORT : SO_REUSEADDR, &optval,
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
