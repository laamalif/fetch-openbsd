/* ISC: SOCKS fixtures */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "harness.h"

static int split_reply;
static long gap_ns = 20000000;
static const unsigned char *bound_addr;
static size_t bound_len;
static const char *eager;

struct socks {
	unsigned short port;
	pid_t pid;
};

static void
relay(int client, int backend)
{
	struct pollfd pfd[2];
	char buf[8192];
	ssize_t n;
	int i, other;

	pfd[0].fd = client;
	pfd[1].fd = backend;
	pfd[0].events = pfd[1].events = POLLIN;
	while (pfd[0].fd != -1 || pfd[1].fd != -1) {
		CHECK(poll(pfd, 2, 10000) > 0);
		for (i = 0; i < 2; i++) {
			if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR)))
				continue;
			other = i == 0 ? backend : client;
			n = read(pfd[i].fd, buf, sizeof(buf));
			if (n == -1 && errno == EINTR)
				continue;
			CHECK(n >= 0);
			if (n == 0) {
				CHECK(shutdown(other, SHUT_WR) == 0);
				pfd[i].fd = -1;
			} else
				CHECK(writeall(other, buf, (size_t)n) == 0);
		}
	}
}

static int
sockswrite(int fd, const void *v, size_t len)
{
	const unsigned char *p = v;
	struct timespec gap = {0, gap_ns};
	size_t i;

	if (!split_reply)
		return writeall(fd, v, len);
	for (i = 0; i < len; i++) {
		if (writeall(fd, p + i, 1) == -1)
			return -1;
		CHECK(nanosleep(&gap, NULL) == 0);
	}
	return 0;
}

static void
socksserve(int fd, unsigned short backend, unsigned char rep,
    unsigned char ver)
{
	unsigned char hdr[4], methods[255], addr[256], port[2];
	unsigned char response[10] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
	char host[256], *seen;
	unsigned char *wire;
	size_t wirelen, payloadlen;
	struct sockaddr_in sin;
	int b;

	CHECK(readexact(fd, hdr, 2) == 0 && hdr[0] == 5);
	CHECK(readexact(fd, methods, hdr[1]) == 0);
	response[0] = ver;
	if (sockswrite(fd, response, 2) == -1)
		return;
	/* A bad greeting version must cause the client to close immediately. */
	if (readexact(fd, hdr, 4) == -1)
		return;
	CHECK(hdr[0] == 5 && hdr[1] == 1);
	switch (hdr[3]) {
	case 3:
		CHECK(readexact(fd, addr, 1) == 0);
		b = addr[0];
		CHECK(readexact(fd, host, b) == 0);
		host[b] = '\0';
		break;
	case 1:
		CHECK(readexact(fd, addr, 4) == 0);
		CHECK(inet_ntop(AF_INET, addr, host, sizeof(host)) != NULL);
		break;
	default:
		CHECK(0);
	}
	CHECK(readexact(fd, port, 2) == 0);
	seen = fmt("%s %u %u\n", host, port[0] * 256 + port[1], hdr[3]);
	putfile("socks.seen", seen, strlen(seen), 0600);
	free(seen);
	response[1] = rep;
	wirelen = bound_addr == NULL ? sizeof(response) : 3 + bound_len;
	payloadlen = eager == NULL ? 0 : strlen(eager);
	wire = xmalloc(wirelen + payloadlen);
	memcpy(wire, response, bound_addr == NULL ? sizeof(response) : 3);
	if (bound_addr != NULL)
		memcpy(wire + 3, bound_addr, bound_len);
	if (payloadlen != 0)
		memcpy(wire + wirelen, eager, payloadlen);
	if (split_reply) {
		if (sockswrite(fd, wire, wirelen) == -1) {
			free(wire);
			return;
		}
		if (payloadlen != 0)
			CHECK(writeall(fd, eager, payloadlen) == 0);
	} else
		CHECK(writeall(fd, wire, wirelen + payloadlen) == 0);
	free(wire);
	if (rep != 0)
		return;
	if (eager != NULL) {
		while (read(fd, host, sizeof(host)) > 0)
			;
		return;
	}
	/* Malformed reply fixtures have no backend and end the stream. */
	if (backend == 0)
		return;
	b = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(b != -1);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(backend);
	CHECK(connect(b, (struct sockaddr *)&sin, sizeof(sin)) == 0);
	relay(fd, b);
	close(b);
}

static struct socks
newsocks(unsigned short backend, unsigned char rep, unsigned char ver)
{
	struct socks s;
	int ln, fd;

	ln = listener(AF_INET, &s.port);
	s.pid = child();
	if (s.pid == 0) {
		fd = accept(ln, NULL, NULL);
		CHECK(fd != -1);
		close(ln);
		socksserve(fd, backend, rep, ver);
		close(fd);
		_exit(0);
	}
	close(ln);
	return s;
}

static pid_t
origin(int ln)
{
	pid_t pid;
	int fd;
	char buf[4096];
	const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n"
	    "Connection: close\r\n\r\n" HELLO;

	pid = child();
	if (pid == 0) {
		fd = accept(ln, NULL, NULL);
		CHECK(fd != -1);
		close(ln);
		do {
			line(fd, buf, sizeof(buf));
			CHECK(buf[0] != '\0');
		} while (strcmp(buf, "\r\n") != 0);
		CHECK(writeall(fd, response, sizeof(response) - 1) == 0);
		close(fd);
		_exit(0);
	}
	return pid;
}

void
TestSOCKS5(void)
{
	unsigned short port;
	int ln = listener(AF_INET, &port);
	pid_t pid = origin(ln);
	struct socks s = newsocks(port, 0, 5);
	char *env = fmt("SOCKS5_PROXY=127.0.0.1:%u", s.port);
	char *url = fmt("http://origin.invalid:%u/hello.txt", port);
	char *seen = fmt("origin.invalid %u 3\n", port);
	struct result r;

	close(ln);
	r = run(ARGS("-q", "-o", "-", url), ARGS(env));
	ok(&r);
	CHECK(r.outlen != 0);
	reap(s.pid);
	reap(pid);
	fileeq("socks.seen", seen, strlen(seen));
	result_free(&r);
	free(env);
	free(url);
	free(seen);
}

void
TestSOCKS5Refused(void)
{
	unsigned short port;
	int ln = listener(AF_INET, &port), rep;
	struct pollfd pfd = { ln, POLLIN, 0 };
	struct socks s;
	struct result r;
	char *env;

	for (rep = 1; rep <= 8; rep++) {
		s = newsocks(port, rep, 5);
		env = fmt("SOCKS5_PROXY=127.0.0.1:%u", s.port);
		r = run(ARGS("-q", "-o", "-",
		    "http://origin.invalid/hello.txt"), ARGS(env));
		bad(&r);
		errhas(&r, "SOCKS5");
		reap(s.pid);
		result_free(&r);
		free(env);
	}
	/* A queued connection would mean the origin was reached. */
	CHECK(poll(&pfd, 1, 0) == 0);
	close(ln);
}

void
TestSOCKS5BadVersion(void)
{
	unsigned short port;
	int ln = listener(AF_INET, &port);
	struct socks s = newsocks(port, 0, 4);
	char *env = fmt("SOCKS5_PROXY=127.0.0.1:%u", s.port);
	struct result r = run(ARGS("-q", "-o", "-",
	    "http://origin.invalid/hello.txt"), ARGS(env));

	bad(&r);
	errhas(&r, "SOCKS5");
	reap(s.pid);
	close(ln);
	result_free(&r);
	free(env);
}

void
TestSOCKS5FragmentedReplies(void)
{
	unsigned short port;
	int ln = listener(AF_INET, &port);
	pid_t pid = origin(ln);
	struct socks s;
	struct result r;
	char *env;

	split_reply = 1;
	s = newsocks(port, 0, 5);
	env = fmt("SOCKS5_PROXY=127.0.0.1:%u", s.port);
	close(ln);
	r = run(ARGS("-q", "-o", "-", "http://origin.invalid/hello.txt"),
	    ARGS(env));
	ok(&r);
	CHECK(r.outlen != 0);
	reap(s.pid);
	reap(pid);
	result_free(&r);
	free(env);
}

static void
payload_case(void)
{
	struct socks s;
	struct result r;
	char *env;

	eager = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
	    "Connection: close\r\n\r\nhello";
	s = newsocks(0, 0, 5);
	env = fmt("SOCKS5_PROXY=127.0.0.1:%u", s.port);
	r = run(ARGS("-q", "-T", "5", "-o", "-",
	    "http://origin.invalid/x"), ARGS(env));
	ok(&r);
	outeq(&r, "hello", 5);
	reap(s.pid);
	result_free(&r);
	free(env);
}

void
TestSOCKS5CoalescedReplyKeepsPayload(void)
{
	payload_case();
}

void
TestSOCKS5ReplyAddressTypes(void)
{
	static const unsigned char ipv4[7] = {1};
	static const unsigned char ipv6[19] = {4};
	static const unsigned char domain[] =
	    {3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g', 0, 80};
	static const unsigned char empty[] = {3, 0, 0, 0};
	static const struct {
		const unsigned char *addr;
		size_t len;
	} cases[] = {
		{ipv4, sizeof(ipv4)}, {ipv6, sizeof(ipv6)},
		{domain, sizeof(domain)}, {empty, sizeof(empty)}
	};
	size_t i;

	gap_ns = 1000000;
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		bound_addr = cases[i].addr;
		bound_len = cases[i].len;
		for (split_reply = 0; split_reply <= 1; split_reply++)
			payload_case();
	}
}

void
TestSOCKS5MalformedReply(void)
{
	static const unsigned char unknown[] = {9, 0, 0, 0, 0, 0, 0};
	static const unsigned char truncated[] = {4, 1, 2};
	struct socks s;
	struct result r;
	char *env;
	int i;

	for (i = 0; i < 2; i++) {
		bound_addr = i == 0 ? unknown : truncated;
		bound_len = i == 0 ? sizeof(unknown) : sizeof(truncated);
		s = newsocks(0, 0, 5);
		env = fmt("SOCKS5_PROXY=127.0.0.1:%u", s.port);
		r = run(ARGS("-q", "-T", "2", "-o", "-",
		    "http://origin.invalid/x"), ARGS(env));
		bad(&r);
		errhas(&r, "SOCKS5");
		reap(s.pid);
		result_free(&r);
		free(env);
	}
}

void
TestSOCKS5TrickleHonoursTimeout(void)
{
	struct socks s;
	struct result r;
	char *env;

	split_reply = 1;
	gap_ns = 400000000;
	s = newsocks(0, 0, 5);
	env = fmt("SOCKS5_PROXY=127.0.0.1:%u", s.port);
	r = run(ARGS("-q", "-T", "1", "-o", "-",
	    "http://origin.invalid/x"), ARGS(env));
	bad(&r);
	CHECK(r.seconds <= 3);
	reap(s.pid);
	result_free(&r);
	free(env);
}
