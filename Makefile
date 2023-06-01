PROG=		splicebench
LDADD=		-levent
DPADD=		${LIBEVENT}
WARNINGS=	yes
BINDIR?=	/usr/local/bin
MANDIR?=	/usr/local/man/man

VERSION=	0.02
CLEANFILES=	splicebench-${VERSION}.tar.gz

.PHONY: dist splicebench-${VERSION}.tar.gz
dist: splicebench-${VERSION}.tar.gz
	@echo ${.OBJDIR}/splicebench-${VERSION}.tar.gz

splicebench-${VERSION}.tar.gz:
	rm -rf splicebench-${VERSION}
	mkdir splicebench-${VERSION}
.for f in README LICENSE Changes Makefile GNUmakefile \
    splicebench.c splicebench.1
	cp ${.CURDIR}/$f splicebench-${VERSION}/
.endfor
	tar -czvf $@ splicebench-${VERSION}
	rm -rf splicebench-${VERSION}

CLEANFILES +=	out

PHONY: test cleanup
.for i in ipv4 ipv6
.for m in copy splice
.for a in listen port bind
test: test-$m-$a-$i
.endfor
.endfor
test: test-splice-udp-$i
.endfor

test: cleanup

cleanup:
	@echo '\n==== cleanup ===='
	-pkill splicebench

.for m in copy splice

test-$m-listen-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench -4 $m 127.0.0.1:4712 | tee log &
	echo $@ | nc -N 127.0.0.1 12345
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-$m-listen-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench -6 $m [::1]:4712 | tee log &
	echo $@ | nc -N ::1 12345
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-$m-port-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench $m 0.0.0.0:4711 127.0.0.1:4712 | tee log &
	echo $@ | nc -N 127.0.0.1 4711
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-$m-port-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench $m [::]:4711 [::1]:4712 | tee log &
	echo $@ | nc -N ::1 4711
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-$m-bind-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench $m 127.0.0.1:4711 127.0.0.1:0 127.0.0.1:4712 | tee log &
	echo $@ | nc -N 127.0.0.1 4711
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-$m-bind-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench $m [::]:4711 [::1]:0 [::1]:4712 | tee log &
	echo $@ | nc -N ::1 4711
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-$m-udp-ipv4:
	@echo '\n==== $@ ===='
	nc -u -l 127.0.0.1 4712 >out &
	./splicebench -u $m 127.0.0.1:4711 127.0.0.1:4712 | tee log &
	{ echo accept; sleep .1; echo $@; } | nc -w1 -u -N 127.0.0.1 4711
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

test-$m-udp-ipv6:
	@echo '\n==== $@ ===='
	nc -u -l ::1 4712 >out &
	./splicebench -u $m [::1]:4711 [::1]:4712 | tee log &
	{ echo estabish; sleep .1; echo $@; } | nc -w1 -u -N ::1 4711
	grep $@ out
	grep "$m len `tail -n1 out | wc -c | tr -d ' '`\$$" log

.endfor

.include <bsd.prog.mk>
