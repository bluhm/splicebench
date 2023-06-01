CFLAGS=		-D_DEFAULT_SOURCE -D_GNU_SOURCE \
		-DLIBBSD_OVERLAY -isystem /usr/include/bsd \
		-isystem /usr/local/include/bsd \
		-Wall
LDFLAGS=	-lbsd -levent
BINDIR?=        /usr/local/bin
MANDIR?=        /usr/local/man/man

.PHONY: all clean install
all:	splicebench

splicebench: splicebench.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f splicebench splicebench.o out

install:
	install -c -m 555 -s splicebench -D -t ${DESTDIR}${BINDIR}
	install -c -m 444 splicebench.1 -D -t ${DESTDIR}${MANDIR}1

.PHONY: test
test:
