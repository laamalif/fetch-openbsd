/* ISC: see LICENSE. CLI, proxy and file URL behavior. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
void
TestHTTPProxy(void)
{
	const char *p = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvia "
	    "proxy\n";
	struct server s = rawserver(p, strlen(p), 0);
	struct result r = run(ARGS("-q", "-o", "-",
	    "http://origin.invalid/file"), ARGS(fmt("HTTP_PROXY=%s", s.url)));
	ok(&r);
	outeq(&r, "via proxy\n", 10);
	CHECK(strstr(requests(&s), "GET http://origin.invalid/file HTTP/"));
}

void
TestNoProxy(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-o", "-", url(&s, "/hello.txt")),
	    ARGS("HTTP_PROXY=http://127.0.0.1:1", "NO_PROXY=127.0.0.1"));
	ok(&r);
	r = run(ARGS("-q", "-o", "-", "--no-proxy=127.0.0.1", url(&s,
	    "/hello.txt")), ARGS("HTTP_PROXY=http://127.0.0.1:1"));
	ok(&r);
}

void
TestFileScheme(void)
{
	unsigned char *p = pattern(10000);
	char *src = fmt("%s/../source-%ld", testdir, (long)getpid()), buf[4096];
	putfile(src, p, 10000, 0644);
	struct result r = run(ARGS("-q", "-o", "out", fmt("file://%s", src)),
	    NULL);
	ok(&r);
	fileeq("out", p, 10000);
	r = run(ARGS("-q", "-o", "out", fmt("file://%s.missing", src)), NULL);
	bad(&r);
	r = run(ARGS("-q", "-l", "-o", "link", fmt("file://%s", src)), NULL);
	ok(&r);
	ssize_t n = readlink("link", buf, sizeof(buf) - 1);
	CHECK(n >= 0);
	buf[n] = 0;
	CHECK(!strcmp(buf, src));
	free(p);
}

void
TestUnwritableOutput(void)
{
	if (geteuid() == 0)
		skip("root bypasses permissions");
	struct server s = httpserver(AF_INET, 0);
	CHECK(mkdir("ro", 0555) == 0);
	struct result r = run(ARGS("-q", "-o", "ro/out", url(&s,
	    "/hello.txt")), NULL);
	bad(&r);
	CHECK(chmod("ro", 0700) == 0);
}

void
TestCLIErrors(void)
{
	const char *const * a[] = {ARGS(NULL), ARGS("-Z", "http://x/"),
	    ARGS("-T", "abc", "http://x/"), ARGS("-S", "1x", "http://x/"),
	    ARGS("-B", "", "http://x/"), ARGS("-w", "x", "http://x/"),
	    ARGS("-m", "-r", "http://x/"), ARGS("-h", "host"), ARGS("-h",
	    "a:b", "-f", "x")};
	for (int i = 0; i < 9; i++) {
		struct result r = run(a[i], NULL);
		CHECK(r.sig == 0 && r.code == 1);
		if (i == 0)
			errhas(&r, "usage: fetch");
	}
}

void
TestUnsupportedScheme(void)
{
	struct result r = run(ARGS("-q", "-o", "out",
	    "gopher://example.org/"), NULL);
	bad(&r);
}

void
TestNoProxyDomainBoundaries(void)
{
	const char *np[] = {"localhost", "LOCALHOST", "ocalhost", "alhost",
	    ".localhost", "*.localhost", "example.org,localhost",
	    "example.org localhost", "*"};
	int direct[] = {1, 1, 0, 0, 0, 0, 1, 1, 1};
	struct server s = httpserver(AF_INET, 0);
	for (int i = 0; i < 9; i++) {
		struct result r = run(ARGS("-q", "-o", "-",
		    fmt("http://localhost:%u/hello.txt", s.port)),
		    ARGS("HTTP_PROXY=http://127.0.0.1:1", fmt("NO_PROXY=%s",
		    np[i])));
		CHECK(!r.sig);
		CHECK((r.code == 0) == direct[i]);
	}
}

void
TestDeprecatedFlagsWarn(void)
{
	struct server s = httpserver(AF_INET, 0);
	const char *f[] = {"-b", "-t"};
	for (int i = 0; i < 2; i++) {
		struct result r = run(ARGS(f[i], "-o", "-", url(&s,
		    "/hello.txt")), NULL);
		ok(&r);
		errhas(&r, fmt("the %s option is deprecated", f[i]));
		CHECK(r.outlen > 0);
	}
}

void
TestStalledBodyUnknownLengthFails(void)
{
	const char *p = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhalf";
	struct server s = rawserver(p, strlen(p), 10);
	struct result r = run(ARGS("-T", "1", "-o", "out", url(&s, "/x")),
	    NULL);
	bad(&r);
	errhas(&r, "timed out");
	nofile("out");
}
