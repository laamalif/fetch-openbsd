PROG=		fetch
SRCS=		main.c sandbox.c \
		common.c fetch.c file.c ftp.c http.c
BUILDFIRST=	ftperr.h httperr.h
MAN=		fetch.1

.PATH:		${.CURDIR}/libfetch

CFLAGS+=	-Wall -DINET6 -DFTP_COMBINE_CWDS
CFLAGS+=	-I${.CURDIR}/libfetch -I${.OBJDIR}
LDADD+=		-ltls -lssl -lcrypto
DPADD+=		${LIBTLS} ${LIBSSL} ${LIBCRYPTO}

CLEANFILES+=	ftperr.h httperr.h

ftperr.h: ftp.errors
	@echo "static struct fetcherr ftp_errlist[] = {" > ${.TARGET}
	@grep -v '^#' ${.ALLSRC} | sort | \
	    while read NUM CAT STRING; do \
		echo "    { $${NUM}, FETCH_$${CAT}, \"$${STRING}\" },"; \
	    done >> ${.TARGET}
	@echo "    { -1, FETCH_UNKNOWN, \"Unknown FTP error\" }" >> ${.TARGET}
	@echo "};" >> ${.TARGET}

httperr.h: http.errors
	@echo "static struct fetcherr http_errlist[] = {" > ${.TARGET}
	@grep -v '^#' ${.ALLSRC} | sort | \
	    while read NUM CAT STRING; do \
		echo "    { $${NUM}, FETCH_$${CAT}, \"$${STRING}\" },"; \
	    done >> ${.TARGET}
	@echo "    { -1, FETCH_UNKNOWN, \"Unknown HTTP error\" }" >> ${.TARGET}
	@echo "};" >> ${.TARGET}

.include <bsd.prog.mk>
