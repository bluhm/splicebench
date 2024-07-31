PROG=		splicebench
LDADD=		-levent
DPADD=		${LIBEVENT}
WARNINGS=	yes
BINDIR?=	/usr/local/bin
MANDIR?=	/usr/local/man/man

VERSION=	1.05
CLEANFILES=	splicebench-${VERSION}.tar.gz*

.PHONY: dist splicebench-${VERSION}.tar.gz
dist: splicebench-${VERSION}.tar.gz
	gpg --armor --detach-sign splicebench-${VERSION}.tar.gz
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

CLEANFILES+=	out log

PHONY: test
.for i in ipv4 ipv6
.for m in copy splice
.for a in listen port bind
test: test-$m-$a-$i
.endfor
test: test-$m-udp-$i
.endfor
.endfor

.for m in copy splice

test-$m-listen-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} -4 127.0.0.1:4712 | tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	echo $@ | nc -N 127.0.0.1 12345
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

test-$m-listen-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} -6 [::1]:4712 | tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	echo $@ | nc -N ::1 12345
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

test-$m-port-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} 0.0.0.0:4711 127.0.0.1:4712 | \
	    tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	echo $@ | nc -N 127.0.0.1 4711
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

test-$m-port-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} [::]:4711 [::1]:4712 | tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	echo $@ | nc -N ::1 4711
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

test-$m-bind-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} 127.0.0.1:4711 127.0.0.1:0 \
	    127.0.0.1:4712 | tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	echo $@ | nc -N 127.0.0.1 4711
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

test-$m-bind-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} [::]:4711 [::1]:0 [::1]:4712 | \
	    tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	echo $@ | nc -N ::1 4711
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

test-$m-udp-ipv4:
	@echo '\n==== $@ ===='
	nc -w5 -u -l 127.0.0.1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} -u 127.0.0.1:4711 127.0.0.1:4712 | \
	    tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	{ echo accept; sleep .1; echo $@; } | nc -w1 -u -N 127.0.0.1 4711
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

test-$m-udp-ipv6:
	@echo '\n==== $@ ===='
	nc -w5 -u -l ::1 4712 >out &
	./splicebench ${m:Mcopy:C/.*/-c/} -u [::1]:4711 [::1]:4712 | tee log &
	for i in `jot 5`; do grep -q 'listen sockname' log && exit 0; \
	    sleep .1; done; exit 1
	{ echo estabish; sleep .1; echo $@; } | nc -w1 -u -N ::1 4711
	grep $@ out
	grep "$m: payload `tail -n1 out | wc -c | tr -d ' '`," log

.endfor

.include <bsd.prog.mk>
