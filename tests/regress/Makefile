PROG= fetch-regress
SRCS= harness.c server.c cases.c test_http.c test_fault.c test_chunk.c \
      test_diag.c test_misc.c test_output.c test_sandbox.c test_range.c \
      test_retry.c test_regress.c test_tls.c test_ftp.c test_socks.c test_verbose.c
CFLAGS+= -Wall -Wextra
LDADD= -ltls -lssl -lcrypto
DPADD= ${LIBTLS} ${LIBSSL} ${LIBCRYPTO}
REGRESS_TARGETS= run-suite
CLEANFILES+= certs/config certs/server.key certs/server.pem \
    certs/other.key certs/other.pem

run-suite: ${PROG}
	sh ${.CURDIR}/certificates.sh
	./${PROG}

.include <bsd.regress.mk>
