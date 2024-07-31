/*
 * Copyright (c) 2023-2024 Alexander Bluhm <bluhm@genua.de>
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
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

int listenfamily = AF_UNSPEC;
char *listenhost, *bindouthost, *connecthost;
char *listenport, *bindoutport, *connectport;
int buffersize, multi, repeat, splicemode = 1, udpmode;
int idle = 1, timeout = 1;
#ifndef __OpenBSD__
uint16_t listensockport;
#endif
struct timeval start, finish;
int has_timedout;

struct ev_splice {
	struct	event ev;
	struct	timeval begin;
	off_t	len;
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
void	resplice_cb(int, short, void *);
void	process_copy(struct ev_splice *, int, int);
void	waitpid_cb(int, short, void *);
void	print_status(const char *, long long, const struct timeval *,
	    const struct timeval *);
int	socket_connect_repeat(void);
int	socket_connect(const char *, const char *, const char *, const char *,
	    struct addrinfo *);
int	socket_bind_connect(struct addrinfo *, const char *,
	    const char *, struct addrinfo *, const char **);
int	socket_connect_unblock(int, int, int, const struct sockaddr *,
	    socklen_t, const struct sockaddr *, socklen_t, const char **);
int	socket_bind(const char *, const char *, struct addrinfo *);
int	socket_bind_listen(int, int, int, struct sockaddr *, socklen_t,
	    const char **);
void	address_parse(const char *, char **, char **);
void	timeout_event(struct event *, int, short, void (*)(int, short, void *),
	    void *);

static void
usage(void)
{
	fprintf(stderr, "usage: splicebench [-46cu] [-b bufsize] [-i idle] "
	    "[-N repeat] [-n multi] [-t timeout] [listen] [bindout] connect\n"
	    "    -4             listen on IPv4\n"
	    "    -6             listen on IPv6\n"
	    "    -b bufsize     set size of send or receive buffer\n"
	    "    -c             copy instead of splice\n"
	    "    -i idle        idle timeout before splicing stops, default 1\n"
	    "    -N repeat      run parallel splices with incremented address\n"
	    "    -n multi       run parallel splices multiple TCP accepts\n"
	    "    -t timeout     global splice timeout, default 1\n"
	    "    -u             splice UDP instead of TCP\n"
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

	while ((ch = getopt(argc, argv, "46b:ci:N:n:t:u")) != -1) {
		switch (ch) {
		case '4':
			listenfamily = AF_INET;
			break;
		case '6':
			listenfamily = AF_INET6;
			break;
		case 'b':
			buffersize = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "buffer size is %s: %s",
				    errstr, optarg);
			break;
		case 'c':
			splicemode = 0;
			break;
		case 'i':
			idle = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "idle is %s: %s",
				    errstr, optarg);
			break;
		case 'N':
			repeat = strtonum(optarg, 0, 256, &errstr);
			if (errstr != NULL)
				errx(1, "repeat number is %s: %s",
				    errstr, optarg);
			break;
		case 'n':
			multi = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "multi number is %s: %s",
				    errstr, optarg);
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

#ifdef __OpenBSD__
	if (splicemode) {
		if (pledge("stdio dns inet", NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio dns inet proc", NULL) == -1)
			err(1, "pledge");
	}
#else
	if (splicemode)
		errx(1, "splice mode only supported on OpenBSD");
#endif
	listenhost = bindouthost = connecthost = NULL;
	listenport = bindoutport = connectport = NULL;
	switch (argc) {
	case 1:
		address_parse(argv[0], &connecthost, &connectport);
		break;
	case 2:
		address_parse(argv[0], &listenhost, &listenport);
		address_parse(argv[1], &connecthost, &connectport);
		break;
	case 3:
		address_parse(argv[0], &listenhost, &listenport);
		address_parse(argv[1], &bindouthost, &bindoutport);
		address_parse(argv[2], &connecthost, &connectport);
		break;
	default:
		usage();
	}
	if (listenport == NULL)
		listenport = "12345";
	if (connectport == NULL)
		connectport = "12345";

	if (timeout) {
		if (gettimeofday(&finish, NULL) == -1)
			err(1, "gettimeofday finish");
		finish.tv_sec += timeout + 1;
		if (udpmode)
			finish.tv_sec += idle;
	}

	event_init();

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		err(1, "signal");

	socket_listen();

	event_dispatch();

	if ((!udpmode || idle) && has_timedout)
		errx(1, "stopped by timeout");

	return 0;
}

void
socket_listen(void)
{
	struct addrinfo hints;
	struct sockaddr_storage ss;
	int lsock, n;
	struct event *ev;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = listenfamily;
	if (udpmode) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}
	hints.ai_flags = AI_PASSIVE;

	lsock = socket_bind(listenhost, listenport, &hints);
	if (gettimeofday(&start, NULL) == -1)
		err(1, "gettimeofday start");
	localinfo_print("listen", lsock, &ss);
#ifndef __OpenBSD__
	if (ss.ss_family == AF_INET)
		listensockport = ((struct sockaddr_in *)(&ss))->sin_port;
	if (ss.ss_family == AF_INET6)
		listensockport = ((struct sockaddr_in6 *)(&ss))->sin6_port;
#endif

	for (n = repeat; n >= 0; n--) {
		const char *cause = NULL;
		socklen_t sslen;

		if ((ev = malloc(sizeof(*ev))) == NULL)
			err(1, "malloc ev listen");

		if (udpmode)
			timeout_event(ev, lsock, EV_READ, receiving_cb, ev);
		else
			timeout_event(ev, lsock, EV_READ, accepting_cb, ev);

		if (n <= 1)
			break;

		switch (ss.ss_family) {
			struct sockaddr_in *sin;
			struct sockaddr_in6 *sin6;

		case AF_INET:
			sin = (struct sockaddr_in *)&ss;
			((uint8_t *)&sin->sin_addr.s_addr)[3]++;
			sslen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&ss;
			((uint8_t *)&sin6->sin6_addr.s6_addr)[15]++;
			sslen = sizeof(struct sockaddr_in6);
			break;
		}
		lsock = socket_bind_listen(ss.ss_family, hints.ai_socktype,
		    hints.ai_protocol, (struct sockaddr *)&ss, sslen, &cause);
		if (lsock == -1)
			err(1, "%s %d", cause, n - 1);
		localinfo_print("listen", lsock, &ss);
	}
}

void
accepting_cb(int lsock, short event, void *arg)
{
	struct event *ev = arg;
	struct sockaddr_storage ss;
	socklen_t sslen;
	static int n;
	int asock, csock;
	struct ev_splice *evs;

	if (event & EV_TIMEOUT) {
		has_timedout = 1;
		close(lsock);
		free(ev);
		return;
	}

	sslen = sizeof(ss);
	asock = accept(lsock, (struct sockaddr *)&ss, &sslen);
	if (asock == -1)
		err(1, "accept");
	nameinfo_print("accept", "peer", &ss, sslen);
	localinfo_print("accept", asock, &ss);

	csock = socket_connect_repeat();

	if ((evs = calloc(1, sizeof(*evs))) == NULL)
		err(1, "malloc ev connect");

	evs->sock = asock;
	timeout_event(&evs->ev, csock, EV_WRITE, connected_cb, evs);
	if (multi > 1 && n != 1) {
		timeout_event(ev, lsock, EV_READ, accepting_cb, ev);
		if (n == 0)
			n = multi;
		n--;
	} else {
		close(lsock);
		free(ev);
	}
}

void
connected_cb(int csock, short event, void *arg)
{
	struct ev_splice *evs = arg;
	int asock = evs->sock;
	struct sockaddr_storage ss;

	if (event & EV_TIMEOUT) {
		has_timedout = 1;
		close(asock);
		close(csock);
		free(evs);
		return;
	}

	foreigninfo_print("connect", csock, &ss);

	if (gettimeofday(&evs->begin, NULL) == -1)
		err(1, "gettimeofday begin");
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
	struct event *ev = arg;
	char buf[64*1024];
	struct sockaddr_storage foreign, local, ss;
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

	if (event & EV_TIMEOUT) {
		has_timedout = 1;
		close(lsock);
		free(ev);
		return;
	}

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
	if (in == -1)
		err(1, "recvmsg");
	foreignlen = msg.msg_namelen;
	local.ss_family = AF_UNSPEC;
	locallen = sizeof(local);

	if (msg.msg_flags & MSG_CTRUNC)
		errx(1, "control message truncated");
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#ifdef __OpenBSD__
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_addr)) &&
		    cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVDSTADDR) {
			sin = (struct sockaddr_in *)&local;
			locallen = sizeof(*sin);
			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(*sin);
			sin->sin_addr = *(struct in_addr *)CMSG_DATA(cmsg);
		}
#endif
#ifdef __linux__
		if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)) &&
		    cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_PKTINFO) {
			const struct in_pktinfo *pi;

			pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
			sin = (struct sockaddr_in *)&local;
			locallen = sizeof(*sin);
			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			sin->sin_port = listensockport;
			sin->sin_addr = pi->ipi_addr;
		}
#endif
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
	if (asock == -1)
		err(1, "socket");
	if (buffersize) {
		if (setsockopt(asock, SOL_SOCKET, SO_RCVBUF, &buffersize,
		    sizeof(buffersize)) == -1)
			err(1, "setsockopt SO_RCVBUF %d", buffersize);
	}
	optval = 1;
	if (setsockopt(asock, SOL_SOCKET, SO_REUSEPORT, &optval,
	    sizeof(optval)) == -1)
		err(1, "setsockopt reuseport");
	if (bind(asock, (struct sockaddr *)&local, locallen) == -1)
		err(1, "bind");
	if (connect(asock, (struct sockaddr *)&foreign, foreignlen) == -1)
		err(1, "connect");

	csock = socket_connect_repeat();
	foreigninfo_print("connect", csock, &ss);

	out = send(csock, buf, in, 0);
	if (out == -1)
		err(1, "send");
	if (out != in)
		errx(1, "partial send %zd of %zd", out, in);

	if ((evs = calloc(1, sizeof(*evs))) == NULL)
		err(1, "malloc ev connect");
	if (gettimeofday(&evs->begin, NULL) == -1)
		err(1, "gettimeofday begin");
#ifdef __OpenBSD__
	if (splicemode)
		dgram_splice(evs, asock, csock);
	else
#endif
		process_copy(evs, asock, csock);

	close(lsock);
	free(ev);
}

int
socket_connect_repeat(void)
{
	struct addrinfo hints;
	static struct sockaddr_storage foreign, local;
	static int n;
	int sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	if (udpmode) {
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
	}

	if (!repeat || n <= 0) {
		sock = socket_connect(connecthost, connectport,
		    bindouthost, bindoutport, &hints);
		memcpy(&foreign, hints.ai_addr, hints.ai_addrlen);
		n = repeat;
	} else {
		const char *cause = NULL;
		socklen_t sslen;

		switch (local.ss_family) {
			struct sockaddr_in *fsin, *lsin;
			struct sockaddr_in6 *fsin6, *lsin6;

		case AF_INET:
			fsin = (struct sockaddr_in *)&foreign;
			lsin = (struct sockaddr_in *)&local;
			((uint8_t *)&fsin->sin_addr.s_addr)[3]++;
			lsin->sin_port = 0;
			sslen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			fsin6 = (struct sockaddr_in6 *)&foreign;
			lsin6 = (struct sockaddr_in6 *)&local;
			((uint8_t *)&fsin6->sin6_addr.s6_addr)[15]++;
			lsin6->sin6_port = 0;
			sslen = sizeof(struct sockaddr_in6);
			break;
		}
		sock = socket_connect_unblock(local.ss_family,
		    hints.ai_socktype, hints.ai_protocol,
		    (struct sockaddr *)&local, sslen,
		    (struct sockaddr *)&foreign, sslen, &cause);
		if (sock == -1)
			err(1, "%s %d", cause, n - 1);
		n--;
	}
	localinfo_print("connect", sock, &local);

	return sock;
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
		err(1, "getsockname %s", name);
	nameinfo_print(name, "sock", ss, sslen);
}

void
nameinfo_print(const char *name, const char *side, struct sockaddr_storage *ss,
    socklen_t sslen)
{
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	int error;

	error = getnameinfo((struct sockaddr *)ss, sslen, host, sizeof(host),
	    serv, sizeof(serv), NI_NUMERICHOST | NI_NUMERICSERV |
	    (udpmode ? NI_DGRAM : 0));
	if (error)
		errx(1, "getnameinfo %s %s: %s",
		    name, side, gai_strerror(error));
	printf("%s %sname: %s %s\n", name, side, host, serv);
}

#ifdef __OpenBSD__
void
stream_splice(struct ev_splice *evs, int from, int to)
{
	if (setsockopt(from, SOL_SOCKET, SO_SPLICE, &to, sizeof(int)) == -1)
		err(1, "setsockopt SO_SPLICE");

	evs->sock = to;
	timeout_event(&evs->ev, from, EV_READ, unsplice_cb, evs);
}

void
dgram_splice(struct ev_splice *evs, int from, int to)
{
	struct splice sp;

	memset(&sp, 0, sizeof(sp));
	sp.sp_fd = to;
	sp.sp_idle.tv_sec = idle;

	if (setsockopt(from, SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp)) == -1)
		err(1, "setsockopt SO_SPLICE");

	evs->sock = to;
	timeout_event(&evs->ev, from, EV_READ, unsplice_cb, evs);
}

void
unsplice_cb(int from, short event, void *arg)
{
	struct ev_splice *evs = arg;
	int to = evs->sock;
	struct timeval end;
	off_t splicelen;
	socklen_t len;
	int error;

	if (event & EV_TIMEOUT) {
		int fd = -1;

		has_timedout = 1;
		if (setsockopt(from, SOL_SOCKET, SO_SPLICE, &fd, sizeof(fd))
		    == -1)
			err(1, "setsockopt SO_SPLICE unsplice");
		/* fall through to print status line */
	}

	if (gettimeofday(&end, NULL) == -1)
		err(1, "gettimeofday end");
	len = sizeof(error);
	if (getsockopt(from, SOL_SOCKET, SO_ERROR, &error, &len) == -1)
		err(1, "getsockopt SO_ERROR");
	if (error == ETIMEDOUT) {
		struct timeval timeo;

		/* last data was seen before idle time */
		timeo.tv_sec = idle;
		timeo.tv_usec = 0;
		timersub(&end, &timeo, &end);
	}
	len = sizeof(splicelen);
	if (getsockopt(from, SOL_SOCKET, SO_SPLICE, &splicelen, &len) == -1)
		err(1, "getsockopt SO_SPLICE");
	splicelen += evs->len;
	if (error == ENOBUFS) {
		evs->len = splicelen;
		evs->sock = from;
		timeout_event(&evs->ev, to, EV_WRITE, resplice_cb, evs);
		return;
	}
	print_status("splice", splicelen, &evs->begin, &end);
	if (error && error != ETIMEDOUT) {
		errno = error;
		err(1, "splice error");
	}

	close(from);
	close(to);
	free(evs);
}

void
resplice_cb(int to, short event, void *arg)
{
	struct ev_splice *evs = arg;
	struct splice sp;
	int from = evs->sock;

	if (event & EV_TIMEOUT) {
		struct timeval end;

		if (gettimeofday(&end, NULL) == -1)
			err(1, "gettimeofday end");
		print_status("splice", evs->len, &evs->begin, &end);

		close(from);
		close(to);
		free(evs);
		return;
	}

	memset(&sp, 0, sizeof(sp));
	sp.sp_fd = to;
	sp.sp_idle.tv_sec = idle;

	if (setsockopt(from, SOL_SOCKET, SO_SPLICE, &sp, sizeof(sp)) == -1) {
		if (errno == ENOBUFS) {
			timeout_event(&evs->ev, to, EV_WRITE, resplice_cb, evs);
			return;
		}
		err(1, "setsockopt SO_SPLICE");
	}

	evs->sock = to;
	timeout_event(&evs->ev, from, EV_READ, unsplice_cb, evs);
}
#endif

void
process_copy(struct ev_splice *evs, int from, int to)
{
	struct timeval timeo;
	int pfds[2];
	pid_t child;

	timerclear(&timeo);
	if (udpmode && idle) {
		timeo.tv_sec = idle;
		if (setsockopt(from, SOL_SOCKET, SO_RCVTIMEO, &timeo,
		    sizeof(timeo)) == -1)
			err(1, "setsockopt SO_RCVTIMEO");
	}
	if (pipe(pfds) == -1)
		err(1, "pipe");
	if (fflush(stdout) != 0)
		err(1, "fflush");

	/* fork a process so that multiple streams copy in parallel */
	child = fork();
	if (child == -1)
		err(1, "fork");

	if (child == 0) {
		/* child */
		struct timeval end;
		char *buf;
		size_t bufsize = 10*1024*1024;
		long long copylen = 0;

		if (close(pfds[0]))
			err(1, "close");
		if ((buf = malloc(bufsize)) == NULL)
			err(1, "malloc copy buf");

		for (;;) {
			ssize_t in, out;

			in = recv(from, buf, bufsize, 0);
			if (in == -1 && errno == EWOULDBLOCK)
				break;
			if (in == -1)
				err(1, "read");
			if (in == 0 && !udpmode)
				break;
			out = send(to, buf, in, 0);
			if (out == -1)
				err(1, "write");
			if (out != in)
				errx(1, "partial write %zd of %zd", out, in);
			copylen += out;
		}

		if (gettimeofday(&end, NULL) == -1)
			err(1, "gettimeofday end");
		timersub(&end, &timeo, &end);
		print_status("copy", copylen, &evs->begin, &end);
		_exit(0);
	}

	/* parent */
	if (close(pfds[1]))
		err(1, "close");
	close(from);
	close(to);

	evs->sock = child;
	timeout_event(&evs->ev, pfds[0], EV_READ, waitpid_cb, evs);
}

void
waitpid_cb(int pfd, short event, void *arg)
{
	struct ev_splice *evs = arg;
	pid_t child = evs->sock;
	int status;

	if (event & EV_TIMEOUT) {
		has_timedout = 1;
		kill(SIGTERM, child);
		/* fall through to collect child */
	}

	if (waitpid(child, &status, 0) == -1)
		err(1, "waitpid");
	if (status != 0)
		errx(1, "copy child: %d", status);

	close(pfd);
	free(evs);
}

void
print_status(const char *action, long long datalen,
    const struct timeval *begin, const struct timeval *end)
{
	struct timeval duration, stop;
	double bits;

	bits = (double)datalen * 8;
	timersub(end, begin, &duration);
	bits /= (double)duration.tv_sec + (double)duration.tv_usec / 1000000;
	if (gettimeofday(&stop, NULL) == -1)
		err(1, "gettimeofday stop");
	fflush(stdout);
	printf("%s: payload %lld, "
	    "begin %lld.%06ld, end %lld.%06ld, "
	    "duration %lld.%06ld, bit/s %g, "
	    "start %lld.%06ld, stop %lld.%06ld\n",
	    action, datalen,
	    (long long)begin->tv_sec, begin->tv_usec,
	    (long long)end->tv_sec, end->tv_usec,
	    (long long)duration.tv_sec, duration.tv_usec, bits,
	    (long long)start.tv_sec, start.tv_usec,
	    (long long)stop.tv_sec, stop.tv_usec);
	fflush(stdout);
}

int
socket_connect(const char *host, const char *serv,
    const char *bindhost, const char *bindserv,
    struct addrinfo *hints)
{
	struct addrinfo *res, *res0;
	static struct sockaddr_storage ss;
	int error, sock;
	const char *cause = NULL;

	error = getaddrinfo(host, serv, hints, &res0);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));
	sock = -1;
	for (res = res0; res; res = res->ai_next) {
		if (bindhost == NULL && bindserv == NULL) {
			sock = socket_connect_unblock(res->ai_family,
			    res->ai_socktype, res->ai_protocol, NULL, 0,
			    res->ai_addr, res->ai_addrlen, &cause);
			hints->ai_family = res->ai_family;
			memcpy(&ss, res->ai_addr, res->ai_addrlen);
			hints->ai_addr = (struct sockaddr *)&ss;
			hints->ai_addrlen = res->ai_addrlen;
		} else {
			sock = socket_bind_connect(res, bindhost, bindserv,
			    hints, &cause);
		}
		if (sock == -1)
			continue;

		break;  /* okay we got one */
	}
	if (sock == -1) {
		err(1, "%s %s%s%s%s%s%s%s", cause,
		    bindhost ? bindhost : "",
		    (bindhost && bindserv) ? " " : "",
		    bindserv ? bindserv : "",
		    (bindhost || bindserv) ? " " : "",
		    host ? host : "",
		    (host && serv) ? " " : "",
		    serv ? serv : "");
	}
	freeaddrinfo(res0);
	return sock;
}

int
socket_bind_connect(struct addrinfo *res, const char *host, const char *serv,
    struct addrinfo *hints, const char **cause)
{
	struct addrinfo *bindres, *bindres0;
	static struct sockaddr_storage ss;
	int error, sock;

	hints->ai_family = res->ai_family;
	hints->ai_socktype = res->ai_socktype;
	hints->ai_protocol = res->ai_protocol;
	hints->ai_flags = AI_PASSIVE;

	error = getaddrinfo(host, serv, hints, &bindres0);
	if (error) {
		errx(1, "getaddrinfo %s%s%s: %s", host ? host : "",
		    (host && serv) ? " " : "", serv ? serv : "",
		    gai_strerror(error));
	}
	sock = -1;
	for (bindres = bindres0; bindres; bindres = bindres->ai_next) {
		sock = socket_connect_unblock(bindres->ai_family,
		    bindres->ai_socktype, bindres->ai_protocol,
		    bindres->ai_addr, bindres->ai_addrlen,
		    res->ai_addr, res->ai_addrlen, cause);
		if (sock == -1)
			continue;
		hints->ai_family = res->ai_family;
		memcpy(&ss, res->ai_addr, res->ai_addrlen);
		hints->ai_addr = (struct sockaddr *)&ss;
		hints->ai_addrlen = res->ai_addrlen;

		break;  /* okay we got one */
	}
	freeaddrinfo(bindres0);
	return sock;
}

int
socket_connect_unblock(int family, int socktype, int protocol,
    const struct sockaddr *bindsa, socklen_t bindsalen,
    const struct sockaddr *sa, socklen_t salen, const char **cause)
{
	int sock, save_errno;

	sock = socket(family, socktype | SOCK_NONBLOCK, protocol);
	if (sock == -1) {
		*cause = "socket";
		return -1;
	}
	if (buffersize) {
		if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
		    &buffersize, sizeof(buffersize)) == -1)
			err(1, "setsockopt SO_SNDBUF %d", buffersize);
	}
	if (bindsa != NULL && bind(sock, bindsa, bindsalen) == -1) {
		*cause = "bind";
		save_errno = errno;
		close(sock);
		errno = save_errno;
		sock = -1;
		return -1;
	}
	if (connect(sock, sa, salen) == -1 && errno != EINPROGRESS) {
		*cause = "connect";
		save_errno = errno;
		close(sock);
		errno = save_errno;
		sock = -1;
		return -1;
	}
	if (fcntl(sock, F_SETFL, 0) == -1)
		err(1, "fcntl F_SETFL clear O_NONBLOCK");
	return sock;
}

int
socket_bind(const char *host, const char *serv, struct addrinfo *hints)
{
	struct addrinfo *res, *res0;
	static struct sockaddr_storage ss;
	int error, sock;
	const char *cause = NULL;

	error = getaddrinfo(host, serv, hints, &res0);
	if (error) {
		errx(1, "getaddrinfo %s%s%s: %s", host ? host : "",
		    (host && serv) ? " " : "", serv ? serv : "",
		    gai_strerror(error));
	}
	sock = -1;
	for (res = res0; res; res = res->ai_next) {
		sock = socket_bind_listen(res->ai_family, res->ai_socktype,
		    res->ai_protocol, res->ai_addr, res->ai_addrlen, &cause);
		if (sock == -1)
			continue;
		hints->ai_family = res->ai_family;
		memcpy(&ss, res->ai_addr, res->ai_addrlen);
		hints->ai_addr = (struct sockaddr *)&ss;
		hints->ai_addrlen = res->ai_addrlen;

		break;  /* okay we got one */
	}
	if (sock == -1) {
		err(1, "%s %s%s%s", cause, host ? host : "",
		    (host && serv) ? " " : "", serv ? serv : "");
	}
	freeaddrinfo(res0);
	return sock;
}

int
socket_bind_listen(int family, int socktype, int protocol,
    struct sockaddr *sa, socklen_t salen, const char **cause)
{
	int sock, optval, save_errno;

	sock = socket(family, socktype, protocol);
	if (sock == -1) {
		*cause = "socket";
		return -1;
	}
	if (buffersize) {
		if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buffersize,
		    sizeof(buffersize)) == -1)
			err(1, "setsockopt SO_RCVBUF %d", buffersize);
	}
	if (udpmode && family == AF_INET) {
		optval = 1;
#ifdef __OpenBSD__
		if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTADDR,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt IP_RECVDSTADDR");
#endif
#ifdef __linux__
		if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt IP_PKTINFO");
#endif
#ifdef __OpenBSD__
		if (setsockopt(sock, IPPROTO_IP, IP_RECVDSTPORT,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt IP_RECVDSTPORT");
#endif
	}
	if (udpmode && family == AF_INET6) {
		optval = 1;
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt IPV6_RECVDSTPORT");
#ifdef __OpenBSD__
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVDSTPORT,
		    &optval, sizeof(optval)) == -1)
			err(1, "setsockopt IPV6_RECVDSTPORT");
#endif
	}
	optval = 1;
	if (setsockopt(sock, SOL_SOCKET, socktype == SOCK_DGRAM ?
	    SO_REUSEPORT : SO_REUSEADDR, &optval, sizeof(optval)) == -1)
		err(1, "setsockopt reuseaddr");
	if (bind(sock, sa, salen) == -1) {
		*cause = "bind";
		save_errno = errno;
		close(sock);
		errno = save_errno;
		return -1;
	}
	if (socktype == SOCK_STREAM) {
		if (listen(sock, 1) == -1)
			err(1, "listen");
	}
	return sock;
}

void
address_parse(const char *address, char **host, char **port)
{
	char *str;

	if ((str = strdup(address)) == NULL)
		err(1, "address %s", address);

	*host = str;
	if (**host == '[') {
		*(*host)++ = '\0';
		str = strchr(*host, ']');
		if (str == NULL)
			errx(1, "address %s: missing ]", address);
		*str++ = '\0';
	}
	*port = strrchr(str, ':');
	if (*port != NULL)
		*(*port)++ = '\0';
	if (**host == '\0')
		*host = NULL;
}

void
timeout_event(struct event *ev, int fd, short events,
    void (*callback)(int, short, void *), void *arg)
{
	struct timeval timeo;

	if (!timerisset(&finish)) {
		event_set(ev, fd, events, callback, arg);
		event_add(ev, NULL);
		return;
	}
	if (gettimeofday(&timeo, NULL) == -1)
		err(1, "gettimeofday timeo");
	if (timercmp(&finish, &timeo, <=)) {
		callback(fd, EV_TIMEOUT, arg);
		return;
	}
	timersub(&finish, &timeo, &timeo);
	event_set(ev, fd, events, callback, arg);
	event_add(ev, &timeo);
}
