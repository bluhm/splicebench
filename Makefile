PROG=		splicebench
LDADD=		-levent
DPADD=		${LIBEVENT}
WARNINGS=	yes
BINDIR?=	/usr/local/bin
MANDIR?=	/usr/local/man/man

PHONY: test
test: test-copy test-splice

.for m in copy splice

test-$m:
	@echo '\n==== $@ ===='
	./splicebench $m 127.0.0.1

.endfor

.include <bsd.prog.mk>
