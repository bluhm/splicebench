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
	rm -f splicebench splicebench.o out log

install:
	install -c -m 555 -s splicebench -D -t ${DESTDIR}${BINDIR}
	install -c -m 444 splicebench.1 -D -t ${DESTDIR}${MANDIR}1

.PHONY: test
test: \
	test-copy-listen-ipv4 test-copy-listen-ipv6 \
	test-copy-port-ipv4 test-copy-port-ipv6 \
	test-copy-bind-ipv4 test-copy-bind-ipv6 \
	test-copy-udp-ipv4 test-copy-udp-ipv6 \
	cleanup

cleanup:
	@echo -e '\n==== cleanup ===='
	-pkill splicebench

test-copy-listen-ipv4:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l 127.0.0.1 4712 >out &
	./splicebench -c -4 127.0.0.1:4712 &
	echo $@ | nc.openbsd -N 127.0.0.1 12345
	grep $@ out

test-copy-listen-ipv6:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l ::1 4712 >out &
	./splicebench -c -6 [::1]:4712 &
	echo $@ | nc.openbsd -N ::1 12345
	grep $@ out

test-copy-port-ipv4:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l 127.0.0.1 4712 >out &
	./splicebench -c 0.0.0.0:4711 127.0.0.1:4712 &
	echo $@ | nc.openbsd -N 127.0.0.1 4711
	grep $@ out

test-copy-port-ipv6:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l ::1 4712 >out &
	./splicebench -c [::]:4711 [::1]:4712 &
	echo $@ | nc.openbsd -N ::1 4711
	grep $@ out

test-copy-bind-ipv4:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l 127.0.0.1 4712 >out &
	./splicebench -c 127.0.0.1:4711 127.0.0.1:0 127.0.0.1:4712 &
	echo $@ | nc.openbsd -N 127.0.0.1 4711
	grep $@ out

test-copy-bind-ipv6:
	@echo -e '\n==== $@ ===='
	nc.openbsd -l ::1 4712 >out &
	./splicebench -c [::]:4711 [::1]:0 [::1]:4712 &
	echo $@ | nc.openbsd -N ::1 4711
	grep $@ out

test-copy-udp-ipv4:
	@echo -e '\n==== $@ ===='
	nc.openbsd -w5 -u -l 127.0.0.1 4712 >out &
	./splicebench -c -u 0.0.0.0:4711 127.0.0.1:4712 | tee log &
	{ echo accept; sleep .1; echo $@; } | \
	    nc.openbsd -w1 -u -N 127.0.0.1 4711
	sleep .1
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-copy-udp-ipv6:
	@echo -e '\n==== $@ ===='
	nc.openbsd -w5 -u -l ::1 4712 >out &
	./splicebench -c -u [::]:4711 [::1]:4712 | tee log &
	{ echo accept; sleep .1; echo $@; } | nc.openbsd -w1 -u -N ::1 4711
	sleep .1
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log
