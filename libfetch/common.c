/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1998-2016 Dag-Erling Smørgrav
 * Copyright (c) 2013 Michael Gmelin <freebsd@grem.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

#include "fetch.h"
#include "common.h"

/* Maximum length of a line, newline included, for fetch_getln() */
#define FETCH_LINE_MAX		65536

/*** Local data **************************************************************/

/*
 * Error messages for resolver errors
 */
static struct fetcherr netdb_errlist[] = {
#ifdef EAI_ADDRFAMILY
	{ EAI_ADDRFAMILY, FETCH_RESOLV, "Address family for host not supported" },
#endif
#ifdef EAI_NODATA
	{ EAI_NODATA,	FETCH_RESOLV,	"No address for host" },
#endif
	{ EAI_AGAIN,	FETCH_TEMP,	"Transient resolver failure" },
	{ EAI_FAIL,	FETCH_RESOLV,	"Non-recoverable resolver failure" },
	{ EAI_NONAME,	FETCH_RESOLV,	"Host does not resolve" },
	{ -1,		FETCH_UNKNOWN,	"Unknown resolver error" }
};

/*
 * SOCKS5 error enumerations
 */
enum SOCKS5_ERR {
/* Protocol errors */
	SOCKS5_ERR_SELECTION,
	SOCKS5_ERR_READ_METHOD,
	SOCKS5_ERR_VER5_ONLY,
	SOCKS5_ERR_NOMETHODS,
	SOCKS5_ERR_NOTIMPLEMENTED,
	SOCKS5_ERR_HOSTNAME_SIZE,
	SOCKS5_ERR_REQUEST,
	SOCKS5_ERR_REPLY,
	SOCKS5_ERR_NON_VER5_RESP,
	SOCKS5_ERR_GENERAL,
	SOCKS5_ERR_NOT_ALLOWED,
	SOCKS5_ERR_NET_UNREACHABLE,
	SOCKS5_ERR_HOST_UNREACHABLE,
	SOCKS5_ERR_CONN_REFUSED,
	SOCKS5_ERR_TTL_EXPIRED,
	SOCKS5_ERR_COM_UNSUPPORTED,
	SOCKS5_ERR_ADDR_UNSUPPORTED,
	SOCKS5_ERR_UNSPECIFIED,
/* Configuration errors */
	SOCKS5_ERR_BAD_HOST,
	SOCKS5_ERR_BAD_PROXY_FORMAT,
	SOCKS5_ERR_BAD_PORT
};

/*
 * Error messages for SOCKS5 errors
 */
static struct fetcherr socks5_errlist[] = {
/* SOCKS5 protocol errors */
	{ SOCKS5_ERR_SELECTION,		FETCH_ABORT,	"SOCKS5: Failed to send selection method" },
	{ SOCKS5_ERR_READ_METHOD,	FETCH_ABORT,	"SOCKS5: Failed to read method" },
	{ SOCKS5_ERR_VER5_ONLY,		FETCH_PROTO,	"SOCKS5: Only version 5 is implemented" },
	{ SOCKS5_ERR_NOMETHODS,		FETCH_PROTO,	"SOCKS5: No acceptable methods" },
	{ SOCKS5_ERR_NOTIMPLEMENTED,	FETCH_PROTO,	"SOCKS5: Method currently not implemented" },
	{ SOCKS5_ERR_HOSTNAME_SIZE,	FETCH_PROTO,	"SOCKS5: Hostname size is above 256 bytes" },
	{ SOCKS5_ERR_REQUEST,		FETCH_PROTO,	"SOCKS5: Failed to request" },
	{ SOCKS5_ERR_REPLY,		FETCH_PROTO,	"SOCKS5: Failed to receive reply" },
	{ SOCKS5_ERR_NON_VER5_RESP,	FETCH_PROTO,	"SOCKS5: Server responded with a non-version 5 response" },
	{ SOCKS5_ERR_GENERAL,		FETCH_ABORT,	"SOCKS5: General server failure" },
	{ SOCKS5_ERR_NOT_ALLOWED,	FETCH_AUTH,	"SOCKS5: Connection not allowed by ruleset" },
	{ SOCKS5_ERR_NET_UNREACHABLE,	FETCH_NETWORK,	"SOCKS5: Network unreachable" },
	{ SOCKS5_ERR_HOST_UNREACHABLE,	FETCH_ABORT,	"SOCKS5: Host unreachable" },
	{ SOCKS5_ERR_CONN_REFUSED,	FETCH_ABORT,	"SOCKS5: Connection refused" },
	{ SOCKS5_ERR_TTL_EXPIRED,	FETCH_TIMEOUT,	"SOCKS5: TTL expired" },
	{ SOCKS5_ERR_COM_UNSUPPORTED,	FETCH_PROTO,	"SOCKS5: Command not supported" },
	{ SOCKS5_ERR_ADDR_UNSUPPORTED,	FETCH_ABORT,	"SOCKS5: Address type not supported" },
	{ SOCKS5_ERR_UNSPECIFIED,	FETCH_UNKNOWN,	"SOCKS5: Unspecified error" },
/* Configuration error */
	{ SOCKS5_ERR_BAD_HOST,		FETCH_ABORT,	"SOCKS5: Bad proxy host" },
	{ SOCKS5_ERR_BAD_PROXY_FORMAT,	FETCH_ABORT,	"SOCKS5: Bad proxy format" },
	{ SOCKS5_ERR_BAD_PORT,		FETCH_ABORT,	"SOCKS5: Bad port" }
};

/* End-of-Line */
static const char ENDL[2] = { '\r', '\n' };


/*** Error-reporting functions ***********************************************/

/*
 * Map error code to string
 */
static struct fetcherr *
fetch_finderr(struct fetcherr *p, int e)
{
	while (p->num != -1 && p->num != e)
		p++;
	return (p);
}

/*
 * Set error code
 */
void
fetch_seterr(struct fetcherr *p, int e)
{
	p = fetch_finderr(p, e);
	fetchLastErrCode = p->cat;
	snprintf(fetchLastErrString, MAXERRSTRING, "%s", p->string);
}

/*
 * Set error code according to errno
 */
void
fetch_syserr(void)
{
	switch (errno) {
	case 0:
		fetchLastErrCode = FETCH_OK;
		break;
	case EPERM:
	case EACCES:
	case EROFS:
	case EAUTH:
	case ENEEDAUTH:
		fetchLastErrCode = FETCH_AUTH;
		break;
	case ENOENT:
	case EISDIR: /* XXX */
		fetchLastErrCode = FETCH_UNAVAIL;
		break;
	case ENOMEM:
		fetchLastErrCode = FETCH_MEMORY;
		break;
	case EBUSY:
	case EAGAIN:
		fetchLastErrCode = FETCH_TEMP;
		break;
	case EEXIST:
		fetchLastErrCode = FETCH_EXISTS;
		break;
	case ENOSPC:
		fetchLastErrCode = FETCH_FULL;
		break;
	case EADDRINUSE:
	case EADDRNOTAVAIL:
	case ENETDOWN:
	case ENETUNREACH:
	case ENETRESET:
	case EHOSTUNREACH:
		fetchLastErrCode = FETCH_NETWORK;
		break;
	case ECONNABORTED:
	case ECONNRESET:
		fetchLastErrCode = FETCH_ABORT;
		break;
	case ETIMEDOUT:
		fetchLastErrCode = FETCH_TIMEOUT;
		break;
	case ECONNREFUSED:
	case EHOSTDOWN:
		fetchLastErrCode = FETCH_DOWN;
		break;
	default:
		fetchLastErrCode = FETCH_UNKNOWN;
	}
	snprintf(fetchLastErrString, MAXERRSTRING, "%s", strerror(errno));
}


/*
 * Print a line on stderr with every control character made visible.  The
 * text may come from the peer (a redirect, a certificate), and a terminal
 * acts on escape sequences.
 */
static void
fetch_emit(int flags, const char *fmt, va_list ap)
{
	char *msg, *vis;
	int serrno = errno;

	if (vasprintf(&msg, fmt, ap) == -1)
		msg = NULL;
	if (msg != NULL && stravis(&vis, msg, flags | VIS_CSTYLE |
	    VIS_OCTAL | VIS_NOSLASH) != -1) {
		fputs(vis, stderr);
		free(vis);
	} else
		fputs("(message lost)", stderr);
	free(msg);
	errno = serrno;
}

/*
 * Emit status message
 */
void
fetch_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fetch_emit(VIS_NL | VIS_TAB, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

/*
 * Emit a debugging message, which carries its own newlines
 */
void
fetch_debug(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fetch_emit(VIS_NL | VIS_TAB, fmt, ap);
	va_end(ap);
}

/*
 * A copy of a URL, as typed or as a server sent it, that is safe to show:
 * without the user name and password, and with control characters made
 * visible.  Returns NULL if out of memory.
 */
char *
fetch_redact(const char *url)
{
	const char *at, *auth, *end;
	char *plain, *vis;

	auth = strstr(url, "://");
	auth = auth != NULL ? auth + 3 : url;
	end = auth + strcspn(auth, "/?#");
	for (at = NULL; end > auth; end--)
		if (end[-1] == '@') {
			at = end;
			break;
		}
	if (at == NULL) {
		if ((plain = strdup(url)) == NULL)
			return (NULL);
	} else if (asprintf(&plain, "%.*s%s", (int)(auth - url), url,
	    at) == -1)
		return (NULL);
	if (stravis(&vis, plain, VIS_NL | VIS_TAB | VIS_CSTYLE |
	    VIS_OCTAL | VIS_NOSLASH) == -1)
		vis = NULL;
	free(plain);
	return (vis);
}

/*
 * Milliseconds to wait for what is left on the clock, as poll() takes them
 */
static int
fetch_deltams(const struct timeval *delta)
{
	if (delta->tv_sec >= INT_MAX / 1000 - 1)
		return (INT_MAX);
	return (delta->tv_sec * 1000 + delta->tv_usec / 1000);
}
#define fetch_verbose(...)						\
	do { if (verbose) fetch_info(__VA_ARGS__); } while (0)


/*** Network-related utility functions ***************************************/

/*
 * Return the default port for a scheme
 */
int
fetch_default_port(const char *scheme)
{
	struct servent *se;

	if ((se = getservbyname(scheme, "tcp")) != NULL)
		return (ntohs(se->s_port));
	if (strcmp(scheme, SCHEME_FTP) == 0)
		return (FTP_DEFAULT_PORT);
	if (strcmp(scheme, SCHEME_HTTP) == 0)
		return (HTTP_DEFAULT_PORT);
	return (0);
}

/*
 * Return the default proxy port for a scheme
 */
int
fetch_default_proxy_port(const char *scheme)
{
	if (strcmp(scheme, SCHEME_FTP) == 0)
		return (FTP_DEFAULT_PROXY_PORT);
	if (strcmp(scheme, SCHEME_HTTP) == 0)
		return (HTTP_DEFAULT_PROXY_PORT);
	return (0);
}


/*
 * Create a connection for an existing descriptor.
 */
conn_t *
fetch_reopen(int sd)
{
	conn_t *conn;
	int flags;

	/* allocate and fill connection structure */
	if ((conn = calloc(1, sizeof(*conn))) == NULL)
		return (NULL);
	flags = fcntl(sd, F_GETFD);
	if (flags != -1 && (flags & FD_CLOEXEC) == 0)
		(void)fcntl(sd, F_SETFD, flags | FD_CLOEXEC);
	flags = fcntl(sd, F_GETFL);
	if (flags != -1 && (flags & O_NONBLOCK) == 0)
		(void)fcntl(sd, F_SETFL, flags | O_NONBLOCK);
	conn->sd = sd;
	++conn->ref;
	return (conn);
}


/*
 * Resolve an address
 */
struct addrinfo *
fetch_resolve(const char *addr, int port, int af)
{
	char hbuf[256], sbuf[8];
	struct addrinfo hints, *res;
	const char *hb, *he, *sep;
	const char *host, *service;
	int err, len;

	/* first, check for a bracketed IPv6 address */
	if (*addr == '[') {
		hb = addr + 1;
		if ((sep = strchr(hb, ']')) == NULL) {
			errno = EINVAL;
			goto syserr;
		}
		he = sep++;
	} else {
		hb = addr;
		sep = hb + strcspn(hb, ":");
		he = sep;
	}

	/* see if we need to copy the host name */
	if (*he != '\0') {
		len = snprintf(hbuf, sizeof(hbuf),
		    "%.*s", (int)(he - hb), hb);
		if (len < 0)
			goto syserr;
		if (len >= (int)sizeof(hbuf)) {
			errno = ENAMETOOLONG;
			goto syserr;
		}
		host = hbuf;
	} else {
		host = hb;
	}

	/* was it followed by a service name? */
	if (*sep == '\0' && port != 0) {
		if (port < 1 || port > 65535) {
			errno = EINVAL;
			goto syserr;
		}
		if (snprintf(sbuf, sizeof(sbuf), "%d", port) < 0)
			goto syserr;
		service = sbuf;
	} else if (*sep != '\0') {
		service = sep + 1;
	} else {
		service = NULL;
	}

	/* resolve */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;
	if ((err = getaddrinfo(host, service, &hints, &res)) != 0) {
		netdb_seterr(err);
		return (NULL);
	}
	return (res);
syserr:
	fetch_syserr();
	return (NULL);
}


/*
 * Bind a socket to a specific local address
 */
int
fetch_bind(int sd, int af, const char *addr)
{
	struct addrinfo *cliai, *ai;
	int err;

	if ((cliai = fetch_resolve(addr, 0, af)) == NULL)
		return (-1);
	for (ai = cliai; ai != NULL; ai = ai->ai_next)
		if ((err = bind(sd, ai->ai_addr, ai->ai_addrlen)) == 0)
			break;
	if (err != 0)
		fetch_syserr();
	freeaddrinfo(cliai);
	return (err == 0 ? 0 : -1);
}


/*
 * SOCKS5 connection initiation, based on RFC 1928
 * Default DNS resolution over SOCKS5
 */
int
fetch_socks5_init(conn_t *conn, const char *host, int port, int verbose)
{
	/*
	 * Size is based on largest packet prefix (4 bytes) +
	 * Largest FQDN (256) + one byte size (1) +
	 * Port (2)
	 */
	unsigned char buf[BUFF_SIZE];
	unsigned char *ptr;
	size_t len;
	int ret = 1;

	fetch_verbose("Initializing SOCKS5 connection: %s:%d", host, port);

	/* Connection initialization */
	ptr = buf;
	*ptr++ = SOCKS_VERSION_5;
	*ptr++ = SOCKS_CONNECTION;
	*ptr++ = SOCKS_RSV;

	if (fetch_write(conn, buf, 3) != 3) {
		ret = SOCKS5_ERR_SELECTION;
		goto fail;
	}

	/* Verify response from SOCKS5 server */
	if (fetch_read_exact(conn, buf, 2) != 0) {
		ret = SOCKS5_ERR_READ_METHOD;
		goto fail;
	}

	ptr = buf;
	if (ptr[0] != SOCKS_VERSION_5) {
		ret = SOCKS5_ERR_VER5_ONLY;
		goto fail;
	}
	if (ptr[1] == SOCKS_NOMETHODS) {
		ret = SOCKS5_ERR_NOMETHODS;
		goto fail;
	}
	else if (ptr[1] != SOCKS5_NOTIMPLEMENTED) {
		ret = SOCKS5_ERR_NOTIMPLEMENTED;
		goto fail;
	}

	/* Send Request */
	*ptr++ = SOCKS_VERSION_5;
	*ptr++ = SOCKS_CONNECTION;
	*ptr++ = SOCKS_RSV;
	/* Encode all targets as a hostname to avoid DNS leaks */
	*ptr++ = SOCKS_ATYP_DOMAINNAME;
	if (strlen(host) > FQDN_SIZE) {
		ret = SOCKS5_ERR_HOSTNAME_SIZE;
		goto fail;
	}
	*ptr++ = strlen(host);
	memcpy(ptr, host, strlen(host));
	ptr = ptr + strlen(host);

	/* port in network byte order, independent of the host's */
	*ptr++ = (port >> 8) & 0xff;
	*ptr++ = port & 0xff;

	if (fetch_write(conn, buf, ptr - buf) != ptr - buf) {
		ret = SOCKS5_ERR_REQUEST;
		goto fail;
	}

	/*
	 * The reply is VER REP RSV ATYP BND.ADDR BND.PORT, and BND.ADDR
	 * is as long as ATYP says.  TCP keeps no message boundaries, so
	 * read exactly that much: more would swallow the start of the
	 * application protocol, less would leave SOCKS bytes in it.
	 */
	if (fetch_read_exact(conn, buf, HEAD_SIZE) != 0) {
		ret = SOCKS5_ERR_REPLY;
		goto fail;
	}

	ptr = buf;
	if (*ptr++ != SOCKS_VERSION_5) {
		ret = SOCKS5_ERR_NON_VER5_RESP;
		goto fail;
	}

	switch (*ptr++) {
	case SOCKS_SUCCESS:
		break;
	case SOCKS_GENERAL_FAILURE:
		ret = SOCKS5_ERR_GENERAL;
		goto fail;
	case SOCKS_CONNECTION_NOT_ALLOWED:
		ret = SOCKS5_ERR_NOT_ALLOWED;
		goto fail;
	case SOCKS_NETWORK_UNREACHABLE:
		ret = SOCKS5_ERR_NET_UNREACHABLE;
		goto fail;
	case SOCKS_HOST_UNREACHABLE:
		ret = SOCKS5_ERR_HOST_UNREACHABLE;
		goto fail;
	case SOCKS_CONNECTION_REFUSED:
		ret = SOCKS5_ERR_CONN_REFUSED;
		goto fail;
	case SOCKS_TTL_EXPIRED:
		ret = SOCKS5_ERR_TTL_EXPIRED;
		goto fail;
	case SOCKS_COMMAND_NOT_SUPPORTED:
		ret = SOCKS5_ERR_COM_UNSUPPORTED;
		goto fail;
	case SOCKS_ADDRESS_NOT_SUPPORTED:
		ret = SOCKS5_ERR_ADDR_UNSUPPORTED;
		goto fail;
	default:
		ret = SOCKS5_ERR_UNSPECIFIED;
		goto fail;
	}

	/* RSV must be zero; ATYP says how much address follows */
	if (*ptr++ != SOCKS_RSV) {
		ret = SOCKS5_ERR_REPLY;
		goto fail;
	}
	switch (*ptr) {
	case SOCKS_ATYP_IPV4:
		len = 4;
		break;
	case SOCKS_ATYP_IPV6:
		len = 16;
		break;
	case SOCKS_ATYP_DOMAINNAME:
		if (fetch_read_exact(conn, buf, 1) != 0) {
			ret = SOCKS5_ERR_REPLY;
			goto fail;
		}
		len = buf[0];
		break;
	default:
		ret = SOCKS5_ERR_ADDR_UNSUPPORTED;
		goto fail;
	}
	/* the bound address and port are of no use to us: consume them */
	if (len + PORT_SIZE > sizeof(buf) ||
	    fetch_read_exact(conn, buf, len + PORT_SIZE) != 0) {
		ret = SOCKS5_ERR_REPLY;
		goto fail;
	}

	return (ret);

fail:
	socks5_seterr(ret);
	return (0);
}

/*
 * Perform SOCKS5 initialization
 */
int
fetch_socks5_getenv(char **host, int *port)
{
	char *socks5env, *endptr, *ext;
	const char *portDelim;
	size_t slen;

	portDelim = ":";
	if ((socks5env = getenv("SOCKS5_PROXY")) == NULL || *socks5env == '\0') {
		*host = NULL;
		*port = -1;
		return (-1);
	}

	/*
	 * IPv6 addresses begin and end in brackets.  Set the port delimiter
	 * accordingly and search for it so we can do appropriate validation.
	 */
	if (socks5env[0] == '[')
		portDelim = "]:";

	slen = strlen(socks5env);
	ext = strstr(socks5env, portDelim);
	if (socks5env[0] == '[') {
		if (socks5env[slen - 1] == ']') {
			*host = strndup(socks5env, slen);
		} else if (ext != NULL) {
			*host = strndup(socks5env, ext - socks5env + 1);
		} else {
			socks5_seterr(SOCKS5_ERR_BAD_PROXY_FORMAT);
			return (0);
		}
	} else {
		*host = strndup(socks5env, ext - socks5env);
	}

	if (*host == NULL)
		return (-1);
	if (ext == NULL) {
		*port = 1080; /* Default port as defined in RFC1928 */
	} else {
		ext += strlen(portDelim);
		errno = 0;
		*port = strtoimax(ext, (char **)&endptr, 10);
		if (*endptr != '\0' || errno != 0 || *port < 0 ||
		    *port > 65535) {
			free(*host);
			*host = NULL;
			socks5_seterr(SOCKS5_ERR_BAD_PORT);
			return (0);
		}
	}

	return (2);
}


static int	 fetch_unmap(const struct sockaddr *, struct in_addr *);

/*
 * Connect sd to sa, giving up after fetchTimeout seconds when that is
 * set.  The socket is made non-blocking; whether the connection really
 * came up is asked of the socket (SO_ERROR), not guessed from what poll
 * reported, as in OpenBSD's nc(1).  Returns 0, or -1 with errno set.
 */
int
fetch_connect_sd(int sd, const struct sockaddr *sa, socklen_t salen)
{
	struct timeval now, timeout, delta;
	struct pollfd pfd;
	socklen_t optlen;
	int deltams, optval, r;

	(void)fcntl(sd, F_SETFL, fcntl(sd, F_GETFL) | O_NONBLOCK);
	if (fetchTimeout > 0) {
		gettimeofday(&timeout, NULL);
		timeout.tv_sec += fetchTimeout;
	}
	if (connect(sd, sa, salen) == 0)
		return (0);
	if (errno != EINPROGRESS)
		return (-1);

	pfd.fd = sd;
	pfd.events = POLLOUT;
	for (;;) {
		deltams = INFTIM;
		if (fetchTimeout > 0) {
			gettimeofday(&now, NULL);
			if (!timercmp(&timeout, &now, >)) {
				errno = ETIMEDOUT;
				return (-1);
			}
			timersub(&timeout, &now, &delta);
			deltams = fetch_deltams(&delta);
		}
		if ((r = poll(&pfd, 1, deltams)) > 0)
			break;
		if (r == -1 && (errno != EINTR || !fetchRestartCalls))
			return (-1);
	}
	optlen = sizeof(optval);
	if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1)
		return (-1);
	if (optval != 0) {
		errno = optval;
		return (-1);
	}
	return (0);
}

/*
 * Accept a connection on the listening socket ls within the timeout,
 * from the host expect only: whoever else reaches the port is dropped
 * and the wait goes on, against the one deadline.  Returns the new
 * descriptor, or -1 with errno set.
 */
int
fetch_accept_sd(int ls, const struct sockaddr *expect)
{
	struct sockaddr_storage ss;
	struct timeval now, timeout, delta;
	struct pollfd pfd;
	socklen_t l;
	int d, deltams, r;

	(void)fcntl(ls, F_SETFL, fcntl(ls, F_GETFL) | O_NONBLOCK);
	if (fetchTimeout > 0) {
		gettimeofday(&timeout, NULL);
		timeout.tv_sec += fetchTimeout;
	}
	pfd.fd = ls;
	pfd.events = POLLIN;
	for (;;) {
		deltams = INFTIM;
		if (fetchTimeout > 0) {
			gettimeofday(&now, NULL);
			if (!timercmp(&timeout, &now, >)) {
				errno = ETIMEDOUT;
				return (-1);
			}
			timersub(&timeout, &now, &delta);
			deltams = fetch_deltams(&delta);
		}
		if ((r = poll(&pfd, 1, deltams)) == -1) {
			if (errno != EINTR || !fetchRestartCalls)
				return (-1);
			continue;
		}
		if (r == 0)
			continue;
		l = sizeof(ss);
		if ((d = accept(ls, (struct sockaddr *)&ss, &l)) == -1) {
			if (errno == EAGAIN || errno == ECONNABORTED ||
			    errno == EINTR)
				continue;
			return (-1);
		}
		if (expect == NULL || fetch_same_host(
		    (struct sockaddr *)&ss, expect))
			return (d);
		close(d);
	}
}

/*
 * Do two socket addresses name the same host, whatever their ports and
 * whether either is an IPv4-mapped IPv6 address?
 */
int
fetch_same_host(const struct sockaddr *a, const struct sockaddr *b)
{
	struct in_addr ia, ib;
	const struct sockaddr_in6 *a6, *b6;

	if (fetch_unmap(a, &ia) && fetch_unmap(b, &ib))
		return (ia.s_addr == ib.s_addr);
	if (a->sa_family != AF_INET6 || b->sa_family != AF_INET6)
		return (0);
	a6 = (const struct sockaddr_in6 *)a;
	b6 = (const struct sockaddr_in6 *)b;
	return (memcmp(&a6->sin6_addr, &b6->sin6_addr,
	    sizeof(a6->sin6_addr)) == 0 &&
	    a6->sin6_scope_id == b6->sin6_scope_id);
}

/* The IPv4 address in sa, if it holds one directly or IPv4-mapped. */
static int
fetch_unmap(const struct sockaddr *sa, struct in_addr *ia)
{
	const struct sockaddr_in6 *s6;

	if (sa->sa_family == AF_INET) {
		*ia = ((const struct sockaddr_in *)sa)->sin_addr;
		return (1);
	}
	if (sa->sa_family != AF_INET6)
		return (0);
	s6 = (const struct sockaddr_in6 *)sa;
	if (!IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr))
		return (0);
	memcpy(ia, &s6->sin6_addr.s6_addr[12], sizeof(*ia));
	return (1);
}

/*
 * Establish a TCP connection to the specified port on the specified host.
 */
conn_t *
fetch_connect(const char *host, int port, int af, int verbose)
{
	struct addrinfo *cais = NULL, *sais = NULL, *cai, *sai;
	const char *bindaddr;
	conn_t *conn = NULL;
	int err = 0, serrno, sd = -1;
	char *sockshost;
	int socksport;

	DEBUGF("---> %s:%d\n", host, port);

	/*
	 * Check if SOCKS5_PROXY env variable is set.  fetch_socks5_getenv
	 * will either set sockshost = NULL or allocate memory in all cases.
	 */
	sockshost = NULL;
	if (!fetch_socks5_getenv(&sockshost, &socksport))
		goto fail;

	/* Not using SOCKS5 proxy */
	if (sockshost == NULL) {
		/* resolve server address */
		fetch_verbose("resolving server address: %s:%d", host, port);
		if ((sais = fetch_resolve(host, port, af)) == NULL)
			goto fail;

		/* resolve client address */
		bindaddr = getenv("FETCH_BIND_ADDRESS");
		if (bindaddr != NULL && *bindaddr != '\0') {
			fetch_verbose("resolving client address: %s", bindaddr);
			if ((cais = fetch_resolve(bindaddr, 0, af)) == NULL)
				goto fail;
		}
	} else {
		/* resolve socks5 proxy address */
		fetch_verbose("resolving SOCKS5 server address: %s:%d",
		    sockshost, socksport);
		if ((sais = fetch_resolve(sockshost, socksport, af)) == NULL) {
			socks5_seterr(SOCKS5_ERR_BAD_HOST);
			goto fail;
		}
	}

	/* try each server address in turn */
	for (err = 0, sai = sais; sai != NULL; sai = sai->ai_next) {
		/* open socket */
		if ((sd = socket(sai->ai_family, SOCK_STREAM, 0)) < 0) {
			err = -1;
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				continue;
			goto syserr;
		}

		/* attempt to bind to client address */
		for (err = 0, cai = cais; cai != NULL; cai = cai->ai_next) {
			if (cai->ai_family != sai->ai_family)
				continue;
			if ((err = bind(sd, cai->ai_addr, cai->ai_addrlen)) == 0)
				break;
		}
		if (err != 0) {
			fetch_verbose("failed to bind to %s", bindaddr);
			goto syserr;
		}

		/* connect, within the timeout, and ask what became of it */
		if ((err = fetch_connect_sd(sd, sai->ai_addr,
		    sai->ai_addrlen)) == 0)
			break;

		/* clean up before next attempt */
		serrno = errno;
		close(sd);
		sd = -1;
		errno = serrno;
	}

	/* all attempts failed */
	if (err != 0) {
		if (sockshost != NULL) {
			fetch_verbose("failed to connect to SOCKS5 server %s:%d",
			    sockshost, socksport);
			socks5_seterr(SOCKS5_ERR_CONN_REFUSED);
			goto fail;
		}
		fetch_verbose("failed to connect to %s:%d", host, port);
		goto syserr;
	}

	if ((conn = fetch_reopen(sd)) == NULL)
		goto syserr;

	if (sockshost != NULL) {
		if (!fetch_socks5_init(conn, host, port, verbose))
			goto fail;
		free(sockshost);
	}
	if (cais != NULL)
		freeaddrinfo(cais);
	if (sais != NULL)
		freeaddrinfo(sais);
	return (conn);
syserr:
	fetch_syserr();
fail:
	if (sockshost != NULL)
		free(sockshost);
	/* Fully close if it was opened; otherwise just don't leak the fd. */
	if (conn != NULL)
		fetch_close(conn);
	else if (sd >= 0)
		close(sd);
	if (cais != NULL)
		freeaddrinfo(cais);
	if (sais != NULL)
		freeaddrinfo(sais);
	return (NULL);
}

/*
 * The TLS configuration is built once, before the program restricts
 * itself with pledge(2) and unveil(2), and shared by all connections.
 * The CA bundle is read by the setter, so no file is opened later.
 */
static struct tls_config	*tls_cfg;
static char			 tls_cfg_err[256];

/*
 * Build the TLS configuration from the environment.  libtls verifies the
 * certificate chain and the host name unless told otherwise, and only
 * enables TLS 1.2 and 1.3.  A failure is remembered and reported when a
 * TLS connection is attempted, so plain HTTP and FTP keep working.
 */
int
fetch_tls_init(int verbose)
{
	struct tls_config *cfg;
	const char *ca_file, *ca_path, *err;
	uint32_t protocols;

	if (tls_cfg != NULL)
		return (0);
	if ((cfg = tls_config_new()) == NULL) {
		(void)strlcpy(tls_cfg_err, "cannot allocate TLS configuration",
		    sizeof(tls_cfg_err));
		return (-1);
	}
	protocols = TLS_PROTOCOLS_DEFAULT;
	if (getenv("SSL_NO_TLS1_2") != NULL)
		protocols &= ~TLS_PROTOCOL_TLSv1_2;
	if (getenv("SSL_NO_TLS1_3") != NULL)
		protocols &= ~TLS_PROTOCOL_TLSv1_3;
	if (tls_config_set_protocols(cfg, protocols) == -1)
		goto fail;
	ca_file = getenv("SSL_CA_CERT_FILE");
	ca_path = getenv("SSL_CA_CERT_PATH");
	if (ca_file == NULL && ca_path == NULL)
		ca_file = tls_default_ca_cert_file();
	if (ca_file != NULL) {
		fetch_verbose("Using CA cert file: %s", ca_file);
		if (tls_config_set_ca_file(cfg, ca_file) == -1)
			goto fail;
	}
	if (ca_path != NULL) {
		fetch_verbose("Using CA cert path: %s", ca_path);
		if (tls_config_set_ca_path(cfg, ca_path) == -1)
			goto fail;
	}
	if (getenv("SSL_NO_VERIFY_PEER") != NULL)
		tls_config_insecure_noverifycert(cfg);
	if (getenv("SSL_NO_VERIFY_HOSTNAME") != NULL)
		tls_config_insecure_noverifyname(cfg);
	tls_cfg = cfg;
	return (0);
fail:
	if ((err = tls_config_error(cfg)) == NULL)
		err = "TLS configuration failed";
	(void)strlcpy(tls_cfg_err, err, sizeof(tls_cfg_err));
	tls_config_free(cfg);
	return (-1);
}

/*
 * Run the TLS handshake on a non-blocking socket.
 */
static int
fetch_tls_handshake(conn_t *conn)
{
	struct timeval now, timeout, delta;
	struct pollfd pfd;
	int deltams, ret;

	if (fetchTimeout > 0) {
		gettimeofday(&timeout, NULL);
		timeout.tv_sec += fetchTimeout;
	}
	deltams = INFTIM;
	pfd.fd = conn->sd;
	for (;;) {
		ret = tls_handshake(conn->tls);
		if (ret == 0)
			return (0);
		if (ret == TLS_WANT_POLLIN)
			pfd.events = POLLIN;
		else if (ret == TLS_WANT_POLLOUT)
			pfd.events = POLLOUT;
		else {
			fetch_info("%s", tls_error(conn->tls));
			return (-1);
		}
		/* check what's left of our timeout */
		if (fetchTimeout > 0) {
			gettimeofday(&now, NULL);
			if (!timercmp(&timeout, &now, >)) {
				errno = ETIMEDOUT;
				fetch_syserr();
				return (-1);
			}
			timersub(&timeout, &now, &delta);
			deltams = fetch_deltams(&delta);
		}
		ret = poll(&pfd, 1, deltams);
		if (ret == 0) {
			fetch_info("TLS handshake timed out");
			return (-1);
		}
		if (ret < 0) {
			if (errno == EINTR && fetchRestartCalls)
				continue;
			return (-1);
		}
	}
}

/*
 * Enable TLS on a connection.
 */
int
fetch_ssl(conn_t *conn, const struct url *URL, int verbose)
{
	const char *s;
	char name[MAXHOSTNAMELEN + 1];
	size_t n;

	if (tls_cfg == NULL) {
		fetch_info("%s", tls_cfg_err[0] != '\0' ? tls_cfg_err :
		    "TLS is not initialised");
		return (-1);
	}
	if ((conn->tls = tls_client()) == NULL) {
		fetch_info("TLS context creation failed");
		return (-1);
	}
	/* the URL parser keeps the brackets of an IPv6 literal */
	n = strlen(URL->host);
	if (n > 2 && URL->host[0] == '[' && URL->host[n - 1] == ']') {
		memcpy(name, URL->host + 1, n - 2);
		name[n - 2] = '\0';
	} else
		strlcpy(name, URL->host, sizeof(name));
	if (tls_configure(conn->tls, tls_cfg) == -1 ||
	    tls_connect_socket(conn->tls, conn->sd, name) == -1) {
		fetch_info("%s", tls_error(conn->tls));
		return (-1);
	}
	if (fetch_tls_handshake(conn) == -1)
		return (-1);
	if (verbose) {
		fetch_info("%s connection established using %s",
		    tls_conn_version(conn->tls), tls_conn_cipher(conn->tls));
		if ((s = tls_peer_cert_subject(conn->tls)) != NULL)
			fetch_info("Certificate subject: %s", s);
		if ((s = tls_peer_cert_issuer(conn->tls)) != NULL)
			fetch_info("Certificate issuer: %s", s);
	}
	return (0);
}

/*
 * Read from or write to a TLS connection.  libtls reports that it needs
 * the socket to become readable or writable (for instance during a
 * renegotiation) with a special return value, which we map to EAGAIN
 * plus the poll events to wait for.
 */
static ssize_t
fetch_tls_read(struct tls *tls, void *buf, size_t len, short *events)
{
	ssize_t rlen;

	rlen = tls_read(tls, buf, len);
	if (rlen == TLS_WANT_POLLIN || rlen == TLS_WANT_POLLOUT) {
		*events = rlen == TLS_WANT_POLLIN ? POLLIN : POLLOUT;
		errno = EAGAIN;
		return (-1);
	}
	if (rlen < 0)
		errno = EPROTO;
	return (rlen);
}

static ssize_t
fetch_tls_write(struct tls *tls, const void *buf, size_t len, short *events)
{
	ssize_t wlen;

	wlen = tls_write(tls, buf, len);
	if (wlen == TLS_WANT_POLLIN || wlen == TLS_WANT_POLLOUT) {
		*events = wlen == TLS_WANT_POLLIN ? POLLIN : POLLOUT;
		errno = EAGAIN;
		return (-1);
	}
	if (wlen < 0)
		errno = EPROTO;
	return (wlen);
}

/*
 * Read from a connection w/ timeout
 */
static ssize_t
fetch_read_by(conn_t *conn, void *buf, size_t len, const struct timeval *by)
{
	struct timeval now, timeout, delta;
	struct pollfd pfd;
	ssize_t rlen, total;
	int deltams;

	if (by != NULL)
		timeout = *by;
	else if (fetchTimeout > 0) {
		gettimeofday(&timeout, NULL);
		timeout.tv_sec += fetchTimeout;
		by = &timeout;
	}

	deltams = INFTIM;
	pfd.fd = conn->sd;
	pfd.events = POLLIN;

	total = 0;
	for (;;) {
		/*
		 * The socket is non-blocking.  Instead of the canonical
		 * poll() -> read(), we do the following:
		 *
		 * 1) call read() or tls_read().
		 * 2) if we received some data, return it.
		 * 3) if read() or tls_read() signaled EOF, return.
		 * 4) if an error occurred, return -1.
		 * 5) if we did not receive any data but we're not at EOF,
		 *    call poll().
		 *
		 * In the SSL case, this is necessary because if we
		 * receive a close notification, we have to call
		 * tls_read() one additional time after we've read
		 * everything we received.
		 *
		 * In the non-SSL case, it may improve performance (very
		 * slightly) when reading small amounts of data.
		 */
		if (conn->tls != NULL)
			rlen = fetch_tls_read(conn->tls, buf, len,
			    &pfd.events);
		else
			rlen = read(conn->sd, buf, len);
		if (rlen > 0) {
			/* something was read */
			total += rlen;
			len -= rlen;
			if (len == 0)
				break;
			/* a partial read is success */
			break;
		} else if (rlen == 0) {
			/* connection closed */
			break;
		} else if (errno != EAGAIN) {
			/* error */
			if (errno == EINTR && fetchRestartCalls)
				continue;
			fetch_syserr();
			break;
		}
		/* check what's left of our timeout */
		if (by != NULL) {
			gettimeofday(&now, NULL);
			if (!timercmp(&timeout, &now, >)) {
				errno = ETIMEDOUT;
				fetch_syserr();
				return (-1);
			}
			timersub(&timeout, &now, &delta);
			deltams = fetch_deltams(&delta);
		}
		/* wait for the socket to become readable */
		if (poll(&pfd, 1, deltams) < 0) {
			if (errno == EAGAIN)
				continue;
			if (errno == EINTR && fetchRestartCalls)
				continue;
			break;
		}
	}
	/* a partial read is success */
	if (rlen < 0 && total == 0)
		return (-1);
	return (total);
}

ssize_t
fetch_read(conn_t *conn, void *buf, size_t len)
{
	return (fetch_read_by(conn, buf, len, NULL));
}

/*
 * Read exactly len bytes, no more, within one timeout for the whole of
 * it, so that a peer cannot stretch the wait by sending a byte just
 * before each deadline.  Returns 0, or -1 on error, timeout or EOF.
 * Unlike fetch_read() it may wait for several segments: it is for
 * protocol framing (the SOCKS5 replies), never for streaming data.
 */
int
fetch_read_exact(conn_t *conn, void *buf, size_t len)
{
	struct timeval deadline, *by;
	unsigned char *p;
	ssize_t r;

	by = NULL;
	if (fetchTimeout > 0) {
		gettimeofday(&deadline, NULL);
		deadline.tv_sec += fetchTimeout;
		by = &deadline;
	}
	p = buf;
	while (len > 0) {
		if ((r = fetch_read_by(conn, p, len, by)) <= 0) {
			if (r == 0)
				errno = ECONNRESET;
			return (-1);
		}
		p += r;
		len -= r;
	}
	return (0);
}


/*
 * Read a line of text from a connection w/ timeout
 */
#define MIN_BUF_SIZE 1024

ssize_t
fetch_getln(conn_t *conn)
{
	char *tmp;
	size_t tmpsize;
	ssize_t rlen;

	/* allocate initial buffer */
	if (conn->buf == NULL) {
		if ((conn->buf = malloc(MIN_BUF_SIZE)) == NULL)
			goto fail;
		conn->line = conn->buf;
		conn->bufsize = MIN_BUF_SIZE;
		conn->buflen = 0;
		conn->pos = 0;
	}

	/* look at the data we already have */
	if (conn->pos < conn->buflen) {
		conn->line = conn->buf + conn->pos;
		while (conn->pos < conn->buflen) {
			if (conn->buf[conn->pos++] == '\n')
				goto found;
			if (conn->buf + conn->pos - conn->line >=
			    FETCH_LINE_MAX) {
				errno = EPROTO;
				goto fail;
			}
		}
		/* reset for the upcoming memmove() */
		conn->pos = conn->line - conn->buf;
	}

	/* move residual data up */
	if (conn->buflen > 0) {
		if (conn->pos < conn->buflen) {
			memmove(conn->buf, conn->buf + conn->pos,
			    conn->buflen - conn->pos);
		}
		conn->buflen -= conn->pos;
		conn->pos -= conn->pos;
		conn->line = conn->buf;
	}

	for (;;) {
		/* read as much as we can right now */
		rlen = fetch_read(conn, conn->buf + conn->buflen,
		    conn->bufsize - conn->buflen - 1);
		/* error */
		if (rlen < 0)
			goto fail;
		/* advance and terminate */
		conn->buflen += rlen;
		conn->buf[conn->buflen] = '\0';
		/* connection closed */
		if (rlen == 0)
			break;
		/* look for a newline */
		while (conn->pos < conn->buflen) {
			if (conn->buf[conn->pos++] == '\n')
				goto found;
			if (conn->pos >= FETCH_LINE_MAX) {
				errno = EPROTO;
				goto fail;
			}
		}
		/* do we need a bigger buffer? */
		if (conn->buflen > conn->bufsize / 2) {
			tmp = conn->buf;
			tmpsize = conn->bufsize * 2;
			if ((tmp = realloc(tmp, tmpsize)) == NULL)
				goto fail;
			conn->line = conn->buf = tmp;
			conn->bufsize = tmpsize;
		}
	}
	/* connection closed, return what's left */
	conn->pos = conn->buflen;
found:
	conn->linelen = (conn->buf + conn->pos) - conn->line;
	if (conn->linelen > 0 && conn->line[conn->linelen - 1] == '\n')
		conn->line[--conn->linelen] = '\0';
	if (conn->linelen > 0 && conn->line[conn->linelen - 1] == '\r')
		conn->line[--conn->linelen] = '\0';
	DEBUGF("<<< %.*s\n", (int)conn->linelen, conn->line);
	return (conn->linelen);
fail:
	conn->line = NULL;
	conn->linelen = 0;
	return (-1);
}


/*
 * Read from a connection, taking previously buffered data into account.
 */
ssize_t
fetch_bufread(conn_t *conn, void *buf, size_t len)
{
	ssize_t rlen;

	/* avoid overflow */
	if (len > SSIZE_MAX)
		len = SSIZE_MAX;

	/* allocate initial buffer */
	if (conn->buf == NULL) {
		conn->bufsize = MIN_BUF_SIZE;
		while (conn->bufsize < len)
			conn->bufsize *= 2;
		if ((conn->buf = malloc(conn->bufsize)) == NULL)
			return (-1);
		conn->buflen = 0;
		conn->pos = 0;
	}
	conn->line = NULL;
	conn->linelen = 0;

	/* return residual data first */
	if (conn->buflen > conn->pos) {
		if (len > conn->buflen - conn->pos)
			rlen = conn->buflen - conn->pos;
		else
			rlen = len;
		memcpy(buf, conn->buf + conn->pos, rlen);
		conn->pos += rlen;
		return (rlen);
	}

	return (fetch_read(conn, buf, len));
}


/*
 * Write to a connection w/ timeout
 */
ssize_t
fetch_write(conn_t *conn, const void *buf, size_t len)
{
	struct iovec iov;

	iov.iov_base = __DECONST(char *, buf);
	iov.iov_len = len;
	return (fetch_writev(conn, &iov, 1));
}

/*
 * Write a vector to a connection w/ timeout
 * Note: can modify the iovec.
 */
ssize_t
fetch_writev(conn_t *conn, struct iovec *iov, int iovcnt)
{
	struct timeval now, timeout, delta;
	struct pollfd pfd;
	ssize_t wlen, total;
	int deltams;

	if (fetchTimeout > 0) {
		gettimeofday(&timeout, NULL);
		timeout.tv_sec += fetchTimeout;
	}

	deltams = INFTIM;
	pfd.fd = conn->sd;
	pfd.events = POLLOUT;

	total = 0;
	for (;;) {
		/*
		 * The socket is non-blocking.  Instead of the canonical
		 * poll() -> write(), we do the following:
		 *
		 * 1) call write() or tls_write().
		 * 2) if we wrote everything, return success.
		 * 3) if write() or tls_write() signaled EOF before we
		 *    wrote everything, return -1.
		 * 4) if an error occurred, return -1.
		 * 5) if we did not write everything but we're not at EOF,
		 *    call poll().
		 */
		if (conn->tls != NULL)
			wlen = fetch_tls_write(conn->tls, iov->iov_base,
			    iov->iov_len, &pfd.events);
		else
			wlen = writev(conn->sd, iov, iovcnt);
		if (wlen > 0) {
			/* something was written */
			total += wlen;
			/* skip iovs which were completely written */
			while (iovcnt > 0 && wlen >= (ssize_t)iov->iov_len) {
				wlen -= iov->iov_len;
				iov++;
				iovcnt--;
			}
			/* are we done? */
			if (iovcnt == 0)
				break;
			/* skip written portion of current iov */
			iov->iov_len -= wlen;
			iov->iov_base = __DECONST(char *, iov->iov_base) + wlen;
			/* a partial write is incomplete */
			continue;
		} else if (wlen == 0) {
			/* connection closed */
			break;
		} else if (errno != EAGAIN) {
			/* error */
			if (errno == EINTR && fetchRestartCalls)
				continue;
			fetch_syserr();
			break;
		}
		/* check what's left of our timeout */
		if (fetchTimeout > 0) {
			gettimeofday(&now, NULL);
			if (!timercmp(&timeout, &now, >)) {
				errno = ETIMEDOUT;
				fetch_syserr();
				return (-1);
			}
			timersub(&timeout, &now, &delta);
			deltams = fetch_deltams(&delta);
		}
		/* wait for the socket to become writeable */
		if (poll(&pfd, 1, deltams) < 0) {
			if (errno == EAGAIN)
				continue;
			if (errno == EINTR && fetchRestartCalls)
				continue;
			return (-1);
		}
	}
	/* a partial write is failure */
	if (iovcnt > 0)
		return (-1);
	return (total);
}


/*
 * What the debugging output may show of an outgoing line: credentials are
 * not echoed, since that output is pasted into bug reports.  The header
 * name stays, so the request can still be followed.
 */
static const char *
fetch_loggable(const char *str, char *buf, size_t buflen)
{
	size_t n;

	if (strncmp(str, "PASS ", 5) == 0) {
		snprintf(buf, buflen, "PASS <hidden>");
		return (buf);
	}
	if (strncasecmp(str, "Authorization:", 14) == 0 ||
	    strncasecmp(str, "Proxy-Authorization:", 20) == 0) {
		n = strcspn(str, ":") + 1;
		snprintf(buf, buflen, "%.*s <hidden>", (int)n, str);
		return (buf);
	}
	return (str);
}

/*
 * Write a line of text to a connection w/ timeout
 */
int
fetch_putln(conn_t *conn, const char *str, size_t len)
{
	struct iovec iov[2];
	char shown[64];
	int ret;

	DEBUGF(">>> %s\n", fetch_loggable(str, shown, sizeof(shown)));
	iov[0].iov_base = __DECONST(char *, str);
	iov[0].iov_len = len;
	iov[1].iov_base = __DECONST(char *, ENDL);
	iov[1].iov_len = sizeof(ENDL);
	if (len == 0)
		ret = fetch_writev(conn, &iov[1], 1);
	else
		ret = fetch_writev(conn, iov, 2);
	if (ret == -1)
		return (-1);
	return (0);
}


/*
 * Close connection
 */
int
fetch_close(conn_t *conn)
{
	int ret;

	if (--conn->ref > 0)
		return (0);
	if (conn->tls != NULL) {
		/* the socket is ours, tls_close() does not close it */
		(void)tls_close(conn->tls);
		tls_free(conn->tls);
		conn->tls = NULL;
	}
	ret = close(conn->sd);
	free(conn->buf);
	free(conn);
	return (ret);
}


/*** Authentication-related utility functions ********************************/

static const char *
fetch_read_word(FILE *f)
{
	static char word[1024];

	if (fscanf(f, " %1023s ", word) != 1)
		return (NULL);
	return (word);
}

/*
 * Locate the netrc file.  The answer is cached: the fallback to the
 * password database is not possible once the program has been pledged.
 */
const char *
fetch_netrc_path(void)
{
	static char fn[PATH_MAX];
	static const char *path;
	static int done;
	struct passwd *pwd;
	const char *p;

	if (done)
		return (path);
	done = 1;
	if ((p = getenv("NETRC")) != NULL) {
		DEBUGF("NETRC=%s\n", p);
		if (snprintf(fn, sizeof(fn), "%s", p) >= (int)sizeof(fn)) {
			fetch_info("$NETRC specifies a file name "
			    "longer than PATH_MAX");
			return (NULL);
		}
	} else {
		if ((p = getenv("HOME")) == NULL) {
			if ((pwd = getpwuid(getuid())) == NULL ||
			    (p = pwd->pw_dir) == NULL)
				return (NULL);
		}
		if (snprintf(fn, sizeof(fn), "%s/.netrc", p) >= (int)sizeof(fn))
			return (NULL);
	}
	path = fn;
	return (path);
}

static int
fetch_netrc_open(void)
{
	const char *fn;
	int fd, serrno;

	if ((fn = fetch_netrc_path()) == NULL)
		return (-1);
	if ((fd = open(fn, O_RDONLY)) < 0) {
		serrno = errno;
		DEBUGF("%s: %s\n", fn, strerror(serrno));
		errno = serrno;
	}
	return (fd);
}

/*
 * Get authentication data for a URL from .netrc
 */
int
fetch_netrc_auth(struct url *url)
{
	const char *word;
	int serrno;
	FILE *f;

	if (url->netrcfd < 0)
		url->netrcfd = fetch_netrc_open();
	if (url->netrcfd < 0)
		return (-1);
	if ((f = fdopen(url->netrcfd, "r")) == NULL) {
		serrno = errno;
		DEBUGF("fdopen(netrcfd): %s", strerror(errno));
		close(url->netrcfd);
		url->netrcfd = -1;
		errno = serrno;
		return (-1);
	}
	rewind(f);
	DEBUGF("searching netrc for %s\n", url->host);
	while ((word = fetch_read_word(f)) != NULL) {
		if (strcmp(word, "default") == 0) {
			DEBUGF("using default netrc settings\n");
			break;
		}
		if (strcmp(word, "machine") == 0 &&
		    (word = fetch_read_word(f)) != NULL &&
		    strcasecmp(word, url->host) == 0) {
			DEBUGF("using netrc settings for %s\n", word);
			break;
		}
	}
	if (word == NULL)
		goto ferr;
	while ((word = fetch_read_word(f)) != NULL) {
		if (strcmp(word, "login") == 0) {
			if ((word = fetch_read_word(f)) == NULL)
				goto ferr;
			if (snprintf(url->user, sizeof(url->user),
				"%s", word) > (int)sizeof(url->user)) {
				fetch_info("login name in .netrc is too long");
				url->user[0] = '\0';
			}
		} else if (strcmp(word, "password") == 0) {
			if ((word = fetch_read_word(f)) == NULL)
				goto ferr;
			if (snprintf(url->pwd, sizeof(url->pwd),
				"%s", word) > (int)sizeof(url->pwd)) {
				fetch_info("password in .netrc is too long");
				url->pwd[0] = '\0';
			}
		} else if (strcmp(word, "account") == 0) {
			if ((word = fetch_read_word(f)) == NULL)
				goto ferr;
			/* XXX not supported! */
		} else {
			break;
		}
	}
	fclose(f);
	url->netrcfd = -1;
	return (0);
ferr:
	serrno = errno;
	fclose(f);
	url->netrcfd = -1;
	errno = serrno;
	return (-1);
}

/*
 * The no_proxy environment variable specifies a set of domains for
 * which the proxy should not be consulted; the contents is a comma-,
 * or space-separated list of domain names.  A single asterisk will
 * override all proxy variables and no transactions will be proxied
 * (for compatibility with lynx and curl, see the discussion at
 * <http://curl.haxx.se/mail/archive_pre_oct_99/0009.html>).
 */
int
fetch_no_proxy_match(const char *host)
{
	const char *no_proxy, *p, *q;
	size_t h_len, d_len;
	int sub;

	if ((no_proxy = getenv("NO_PROXY")) == NULL &&
	    (no_proxy = getenv("no_proxy")) == NULL)
		return (0);

	/* asterisk matches any hostname */
	if (strcmp(no_proxy, "*") == 0)
		return (1);

	h_len = strlen(host);
	p = no_proxy;
	do {
		/* position p at the beginning of a domain suffix */
		while (*p == ',' || isspace((unsigned char)*p))
			p++;

		/* position q at the first separator character */
		for (q = p; *q; ++q)
			if (*q == ',' || isspace((unsigned char)*q))
				break;

		/*
		 * An entry names a host and the domain below it:
		 * "example.com" matches example.com and www.example.com,
		 * not notexample.com.  A leading dot, or "*.", asks for the
		 * subdomains only.
		 */
		d_len = q - p;
		sub = 0;
		if (d_len > 1 && p[0] == '*' && p[1] == '.') {
			p++;
			d_len--;
		}
		if (d_len > 1 && p[0] == '.') {
			p++;
			d_len--;
			sub = 1;
		}
		if (d_len > 0 && h_len >= d_len &&
		    strncasecmp(host + h_len - d_len, p, d_len) == 0 &&
		    (h_len == d_len ? !sub : host[h_len - d_len - 1] == '.')) {
			/* domain name matches */
			return (1);
		}

		p = q + 1;
	} while (*q);

	return (0);
}
