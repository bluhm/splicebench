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
test: \
	test-listen-ipv4 test-listen-ipv6 \
	test-port-ipv4 test-port-ipv6 \
	test-bind-ipv4 test-bind-ipv6

test-listen-ipv4:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l 127.0.0.1 4712 >out &
	./splicebench -4 copy 127.0.0.1:4712 &
	echo $@ | nc.openbsd -N 127.0.0.1 12345
	grep $@ out

test-listen-ipv6:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l ::1 4712 >out &
	./splicebench -6 copy [::1]:4712 &
	echo $@ | nc.openbsd -N ::1 12345
	grep $@ out

test-port-ipv4:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l 127.0.0.1 4712 >out &
	./splicebench copy 0.0.0.0:4711 127.0.0.1:4712 &
	echo $@ | nc.openbsd -N 127.0.0.1 4711
	grep $@ out

test-port-ipv6:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l ::1 4712 >out &
	./splicebench copy [::]:4711 [::1]:4712 &
	echo $@ | nc.openbsd -N ::1 4711
	grep $@ out

test-bind-ipv4:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l 127.0.0.1 4712 >out &
	./splicebench copy 127.0.0.1:4711 127.0.0.1:0 127.0.0.1:4712 &
	echo $@ | nc.openbsd -N 127.0.0.1 4711
	grep $@ out

test-bind-ipv6:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l ::1 4712 >out &
	./splicebench copy [::]:4711 [::1]:0 [::1]:4712 &
	echo $@ | nc.openbsd -N ::1 4711
	grep $@ out
