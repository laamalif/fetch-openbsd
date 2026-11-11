/* ISC: see LICENSE. Malformed and interrupted HTTP responses. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
static struct result
rawget(const char *p, int stall)
{
	struct server s = rawserver(p, strlen(p), stall);
	if (stall)
		return run(ARGS("-q", "-T", "1", "-o", "out",
		    url(&s, "/x")), NULL);
	return run(ARGS("-q", "-o", "out", url(&s, "/x")), NULL);
}

void
TestTruncatedBody(void)
{
	struct result r = rawget("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: "
	    "close\r\n\r\nshort response", 0);
	bad(&r);
	errhas(&r, "truncated");
}

void
TestCloseWithoutResponse(void)
{
	struct result r = rawget("", 0);
	bad(&r);
}

void
TestCloseAfterHeaders(void)
{
	struct result r = rawget("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", 0);
	bad(&r);
}

void
TestTruncatedChunked(void)
{
	struct result r = rawget("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	    "10\r\nonly-part", 0);
	bad(&r);
}

void
TestInvalidStatusLine(void)
{
	const char *p[] = {"garbage\r\n\r\n", "HTTP/1.1 abc OK\r\n\r\n",
	    "SSH-2.0-OpenSSH\r\n"};
	for (int i = 0; i < 3; i++) {
		struct result r = rawget(p[i], 0);
		bad(&r);
	}
}

void
TestMalformedHeaders(void)
{
	struct result r = rawget("HTTP/1.1 200 OK\r\nContent-Length: banana\r\n\r\nbody", 0);
	CHECK(r.sig == 0 && (r.code == 0 || r.code == 1));
}

void
TestHTTP10NoLength(void)
{
	struct result r = rawget("HTTP/1.0 200 OK\r\n\r\nuntil close", 0);
	ok(&r);
	fileeq("out", "until close", 11);
}

void
TestStallAfterHeadersTimeout(void)
{
	struct result r = rawget("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc", 10);
	bad(&r);
	CHECK(r.seconds < 6);
}

void
TestConnectionRefused(void)
{
	unsigned short port;
	int fd = listener(AF_INET, &port);
	CHECK(fd >= 0);
	close(fd);
	struct result r = run(ARGS("-q", "-o", "out",
	    fmt("http://127.0.0.1:%u/x", port)), NULL);
	bad(&r);
}

void
TestDNSFailure(void)
{
	if (!resolver_answers())
		skip("resolver does not answer .invalid lookups promptly");
	struct result r = run(ARGS("-q", "-T", "2", "-o", "out",
	    "http://does-not-exist.invalid/x"), NULL);
	bad(&r);
}

void
TestIPv6Literal(void)
{
	unsigned short port;
	int fd = listener(AF_INET6, &port);
	if (fd < 0)
		skip("no IPv6 loopback");
	close(fd);
	struct server s = httpserver(AF_INET6, 0);
	struct result r = run(ARGS("-q", "-o", "-", url(&s, "/hello.txt")),
	    NULL);
	if (strstr(r.err, "Address family"))
		skip("resolver AI_ADDRCONFIG refuses IPv6");
	ok(&r);
	CHECK(!strncmp(r.out, "hello", 5));
}

void
TestForceIPv4(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-4", "-o", "-",
	    fmt("http://localhost:%u/hello.txt", s.port)), NULL);
	ok(&r);
}
