/* ISC: see LICENSE. Minimal scripted servers, not production protocol code. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <tls.h>
#include "server.h"
static unsigned int serial;
static int
sendbuf(int fd, struct tls *t, const void *v, size_t n)
{
	const char *p = v;
	ssize_t z;
	while (n) {
		z = t ? tls_write(t, p, n) : write(fd, p, n);
		if (z < 0 && errno == EINTR)
			continue;
		if (z <= 0)
			return -1;
		p += z;
		n -= z;
	}
	return 0;
}

static int
request(int fd, struct tls *t, char *p, size_t n)
{
	size_t i = 0;
	ssize_t z;
	while (i + 1 < n) {
		z = t ? tls_read(t, p + i, 1) : read(fd, p + i, 1);
		if (z <= 0)
			return -1;
		p[++i] = 0;
		if (i >= 4 && !memcmp(p + i - 4, "\r\n\r\n", 4))
			return 0;
	}
	return -1;
}

static void
respond(int fd, struct tls *t, const char *req)
{
	char method[16], path[4096], *p, *body = NULL, *head;
	size_t n = 0, start = 0;
	int code = 200;
	CHECK(sscanf(req, "%15s %4095s", method, path) == 2);
	if ((p = strchr(path, '?')))
		*p = 0;
	if (!strncmp(path, "/delay/", 7)) {
		sleep(10);
		return;
	}
	if (!strcmp(path, "/loop") || !strncmp(path, "/redirect/",
	    10) || !strncmp(path, "/redirect-code/", 15)) {
		char *dest = "/hello.txt";
		if (!strcmp(path, "/loop"))
			dest = "/loop";
		else if (!strncmp(path, "/redirect/",
		    10) && atoi(path + 10) > 0)
			dest = fmt("/redirect/%d", atoi(path + 10) - 1);
		code = !strncmp(path, "/redirect-code/",
		    15) ? atoi(path + 15) : 302;
		head = fmt("HTTP/1.1 %d Redirect\r\nLocation: %s\r\n"
		    "Content-Length: 0\r\nConnection: close\r\n\r\n", code, dest);
		sendbuf(fd, t, head, strlen(head));
		free(head);
		return;
	}
	if (!strncmp(path, "/status/", 8)) {
		code = atoi(path + 8);
		head = fmt("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: "
		    "close\r\n\r\n", code, code == 404 ? "Not Found" : "Error");
		sendbuf(fd, t, head, strlen(head));
		free(head);
		return;
	}
	if (!strcmp(path, "/basic") || !strcmp(path, "/challenge")) {
		if (!strstr(req, "Authorization: Basic YWxpY2U6czNjcmV0\r\n")) {
			p = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic "
			    "realm=\"test\"\r\nContent-Length: 0\r\nConnection: "
			    "close\r\n\r\n";
			sendbuf(fd, t, p, strlen(p));
			return;
		}
		body = strdup(!strcmp(path,
		    "/basic") ? "authorized\n" : "authed\n");
		n = strlen(body);
	} else if (!strncmp(path, "/bytes/", 7)) {
		n = strtoul(path + 7, NULL, 10);
		CHECK(n <= 64 * 1024 * 1024);
		body = (char *)pattern(n);
	} else if (!strcmp(path, "/chunked")) {
		p = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
		    "Connection: close\r\n\r\n";
		sendbuf(fd, t, p, strlen(p));
		for (int i = 0; i < 50; i++) {
			head = fmt("9\r\nchunk %02d\n\r\n", i);
			sendbuf(fd, t, head, strlen(head));
			free(head);
		}
		sendbuf(fd, t, "0\r\n\r\n", 5);
		return;
	} else {
		body = strdup(HELLO);
		n = strlen(body);
	}
	p = strstr(req, "If-Modified-Since: ");
	if (p) {
		struct tm tm;
		memset(&tm, 0, sizeof(tm));
		if (strptime(p + 19, "%a, %d %b %Y %H:%M:%S GMT",
		    &tm) && timegm(&tm) >= MODTIME) {
			head = "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
			sendbuf(fd, t, head, strlen(head));
			free(body);
			return;
		}
	}
	p = strstr(req, "Range: bytes=");
	if (p) {
		start = strtoull(p + 13, NULL, 10);
		if (start >= n) {
			head = fmt("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: "
			    "bytes */%zu\r\nContent-Length: 0\r\nConnection: "
			    "close\r\n\r\n", n);
			sendbuf(fd, t, head, strlen(head));
			free(head);
			free(body);
			return;
		}
		code = 206;
	}
	char *range = code == 206 ? fmt("Content-Range: bytes %zu-%zu/%zu\r\n", start, n - 1, n) : strdup("");
	head = fmt("HTTP/1.1 %d OK\r\nContent-Length: %zu\r\n"
	    "%sLast-Modified: Thu, 02 Jan 2020 03:04:05 GMT\r\n"
	    "Connection: close\r\n\r\n",
	    code, n - start, range);
	sendbuf(fd, t, head, strlen(head));
	if (strcmp(method, "HEAD"))
		sendbuf(fd, t, body + start, n - start);
	free(head);
	free(body);
	free(range);
}

static struct server
start(int af, int secure, const void *raw, size_t n, int delay)
{
	struct server s;
	int fd = listener(af, &s.port);
	CHECK(fd >= 0);
	s.url = fmt("%s://%s:%u", secure ? "https" : "http",
	    af == AF_INET6 ? "[::1]" : "127.0.0.1", s.port);
	/* Fixture logs live outside the fetch working directory. */
	s.log = fmt("%s/../requests-%ld-%u", testdir, (long)getpid(), serial++);
	putfile(s.log, "", 0, 0600);
	s.pid = child();
	if (!s.pid) {
		struct tls *ctx = NULL, *conn;
		struct tls_config *cfg = NULL;
		if (secure) {
			cfg = tls_config_new();
			CHECK(cfg != NULL);
			CHECK(tls_config_set_cert_file(cfg,
			    fmt("%s/certs/server.pem", suitedir)) == 0);
			CHECK(tls_config_set_key_file(cfg,
			    fmt("%s/certs/server.key", suitedir)) == 0);
			ctx = tls_server();
			CHECK(ctx != NULL);
			CHECK(tls_configure(ctx, cfg) == 0);
		}
		for (;;) {
			int c = accept(fd, NULL, NULL);
			if (c < 0) {
				if (errno == EINTR)
					continue;
				_exit(2);
			}
			char req[32768];
			conn = NULL;
			if (secure && tls_accept_socket(ctx, &conn, c) < 0) {
				close(c);
				continue;
			}
			if (request(c, conn, req, sizeof(req)) == 0) {
				record(s.log, req);
				if (raw) {
					sendbuf(c, conn, raw, n);
					if (delay)
						sleep(delay);
				} else
					respond(c, conn, req);
			}
			if (conn) {
				tls_close(conn);
				tls_free(conn);
			}
			close(c);
		}
	}
	close(fd);
	return s;
}

struct server
httpserver(int af, int secure)
{
	return start(af, secure, NULL, 0, 0);
}

struct server
rawserver(const void *p, size_t n, int delay)
{
	return start(AF_INET, 0, p, n, delay);
}

struct server
redirectserver(const char *to, int secure)
{
	char *r = fmt("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: "
	    "0\r\nConnection: close\r\n\r\n", to);
	struct server s = start(AF_INET, secure, r, strlen(r), 0);
	free(r);
	return s;
}

char *
url(struct server *s, const char *path)
{
	return fmt("%s%s", s->url, path);
}

char *
requests(struct server *s)
{
	return getfile(s->log, NULL);
}

int
request_count(struct server *s)
{
	char *r = requests(s), *p = r;
	int n = 0;
	while ((p = strstr(p, "\r\n\r\n"))) {
		n++;
		p += 4;
	}
	free(r);
	return n;
}
