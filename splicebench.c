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

#include <err.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int	socket_bind(const char *, const char *, struct addrinfo *);
void	address_parse(const char *, char **, char **);

static void
usage(void)
{
	fprintf(stderr, "usage: splicebench splice [listen [bindout]] connect\n"
	    "port, bind address"
	    );
        exit(2);
}

int
main(int argc, char *argv[])
{
	int ch, splicemode;
	char *listenhost, *bindouthost, *connecthost;
	char *listenport, *bindoutport, *connectport;
	int listensock, acceptsock, connectsock;
        struct addrinfo hints;

        if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
                err(1, "setvbuf");

        while ((ch = getopt(argc, argv, "")) != -1) {
                switch (ch) {
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
                splicemode = 1;
                setprogname("splicebench splice");
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

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

	listensock = socket_bind(listenhost, listenport, &hints);

	return 0;
}

int
socket_bind(const char *host, const char *service, struct addrinfo *hints)
{
        struct addrinfo *res, *res0;
        int error, sock;
        int save_errno;
        const char *cause = NULL;

        error = getaddrinfo(host, service, hints, &res0);
        if (error)
                errx(1, "getaddrinfo '%s%s%s': %s", host ? host : "",
		    (host && service) ? "' '" : "", service ? service : "",
		    gai_strerror(error));
        sock = -1;
        for (res = res0; res; res = res->ai_next) {
                sock = socket(res->ai_family, res->ai_socktype,
                    res->ai_protocol);
                if (sock == -1) {
                        cause = "socket";
                        continue;
                }

                if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
                        cause = "bind";
                        save_errno = errno;
                        close(sock);
                        errno = save_errno;
                        sock = -1;
                        continue;
                }

                break;  /* okay we got one */
        }
        if (sock == -1) {
                err(1, "%s '%s%s%s'", cause, host ? host : "",
		    (host && service) ? "' '" : "", service ? service : "");
	}
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
                (*host)++;
                str = strchr(*host, ']');
                if (str == NULL)
			errx(1, "address '%s': missing ]", address);
                *str++ = '\0';
        }
        *port = strrchr(str, ':');
        if (*port != NULL)
                *(*port)++ = '\0';
}
