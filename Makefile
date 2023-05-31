PROG=		splicebench
LDADD=		-levent
DPADD=		${LIBEVENT}
WARNINGS=	yes
BINDIR?=	/usr/local/bin
MANDIR?=	/usr/local/man/man

PHONY: test

.for i in ipv4 ipv6
.for a in listen port bind
.for m in copy splice
test: test-$m-$a-$i
.endfor
.endfor
.endfor

CLEANFILES +=	out

.for m in copy splice

test-$m-listen-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench -4 $m 127.0.0.1:4712 &
	echo $@ | nc -N 127.0.0.1 12345
	grep $@ out

test-$m-listen-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench -6 $m [::1]:4712 &
	echo $@ | nc -N ::1 12345
	grep $@ out

test-$m-port-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench $m 0.0.0.0:4711 127.0.0.1:4712 &
	echo $@ | nc -N 127.0.0.1 4711
	grep $@ out

test-$m-port-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench $m [::]:4711 [::1]:4712 &
	echo $@ | nc -N ::1 4711
	grep $@ out

test-$m-bind-ipv4:
	@echo '\n==== $@ ===='
	nc -l 127.0.0.1 4712 >out &
	./splicebench $m 127.0.0.1:4711 127.0.0.1:0 127.0.0.1:4712 &
	echo $@ | nc -N 127.0.0.1 4711
	grep $@ out

test-$m-bind-ipv6:
	@echo '\n==== $@ ===='
	nc -l ::1 4712 >out &
	./splicebench $m [::]:4711 [::1]:0 [::1]:4712 &
	echo $@ | nc -N ::1 4711
	grep $@ out

.endfor

.include <bsd.prog.mk>
