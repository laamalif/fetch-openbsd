/* ISC: see LICENSE. Real libtls servers and the actual fetch executable. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
static char *
ca(void)
{
	return fmt("--ca-cert=%s/certs/server.pem", suitedir);
}

void
TestTLSUntrustedRejected(void)
{
	struct server s = httpserver(AF_INET, 1);
	struct result r = run(ARGS("-q", "-o", "out",
	    fmt("--ca-cert=%s/certs/other.pem", suitedir), url(&s,
	    "/hello.txt")), NULL);
	bad(&r);
	r = run(ARGS("-q", "-o", "out", url(&s, "/hello.txt")), NULL);
	bad(&r);
}

void
TestTLSNoVerifyPeer(void)
{
	struct server s = httpserver(AF_INET, 1);
	struct result r = run(ARGS("-q", "-o", "-", "--no-verify-peer",
	    url(&s, "/hello.txt")), NULL);
	ok(&r);
	outeq(&r, HELLO, sizeof(HELLO) - 1);
}

void
TestTLSTrustedCA(void)
{
	struct server s = httpserver(AF_INET, 1);
	struct result r = run(ARGS("-q", "-o", "-", ca(), url(&s,
	    "/hello.txt")), NULL);
	ok(&r);
	r = run(ARGS("-q", "-o", "-", url(&s, "/hello.txt")),
	    ARGS(fmt("SSL_CA_CERT_FILE=%s/certs/server.pem", suitedir)));
	ok(&r);
}

void
TestTLSBinaryIntegrity(void)
{
	struct server s = httpserver(AF_INET, 1);
	struct result r = run(ARGS("-q", "-o", "out", ca(), url(&s,
	    "/bytes/3000000")), NULL);
	ok(&r);
	unsigned char *p = pattern(3000000);
	fileeq("out", p, 3000000);
	free(p);
}

void
TestTLSIPv6Literal(void)
{
	unsigned short port;
	int fd = listener(AF_INET6, &port);
	if (fd < 0)
		skip("no IPv6 loopback");
	close(fd);
	struct server s = httpserver(AF_INET6, 1);
	struct result r = run(ARGS("-q", "-o", "-", ca(), url(&s,
	    "/hello.txt")), NULL);
	if (strstr(r.err, "Address family"))
		skip("resolver AI_ADDRCONFIG refuses IPv6");
	ok(&r);
	r = run(ARGS("-q", "-o", "out", fmt("--ca-cert=%s/certs/other.pem",
	    suitedir), url(&s, "/hello.txt")), NULL);
	bad(&r);
}

void
TestTLSHostnameMismatch(void)
{
	struct server s = httpserver(AF_INET, 1);
	char *u = fmt("https://localhost:%u/hello.txt", s.port);
	struct result r = run(ARGS("-q", "-4", "-o", "out", ca(), u), NULL);
	bad(&r);
	r = run(ARGS("-q", "-4", "-o", "-", ca(), "--no-verify-hostname", u),
	    NULL);
	ok(&r);
}

void
TestTLSPlainServer(void)
{
	const char response[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
	    "Connection: close\r\n\r\n";
	unsigned short port;
	pid_t p;
	int fd = listener(AF_INET, &port);
	struct result r;

	CHECK(fd >= 0);
	p = child();
	if (p == 0) {
		unsigned char header[5];
		unsigned char *record;
		size_t len;
		int c = accept(fd, NULL, NULL);

		CHECK(c >= 0);
		CHECK(readexact(c, header, sizeof(header)) == 0);
		CHECK(header[0] == 22); /* TLS handshake record. */
		len = ((size_t)header[3] << 8) | header[4];
		CHECK(len > 0 && len <= 16384);
		record = xmalloc(len);
		CHECK(readexact(c, record, len) == 0);
		free(record);
		CHECK(writeall(c, response, sizeof(response) - 1) == 0);
		close(c);
		close(fd);
		_exit(0);
	}
	close(fd);
	r = run(ARGS("-q", "-o", "out", "--no-verify-peer",
	    fmt("https://127.0.0.1:%u/hello.txt", port)), NULL);
	bad(&r);
	reap(p);
}
