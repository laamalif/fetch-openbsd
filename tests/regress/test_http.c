/* ISC: see LICENSE. Black-box HTTP assertions. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
#define GET(s,p) run(ARGS("-q","-o","-",url(&(s),(p))),NULL)
void
TestGETDefaultFilename(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", url(&s, "/hello.txt")), NULL);
	ok(&r);
	fileeq("hello.txt", HELLO, sizeof(HELLO) - 1);
}

void
TestGETToStdout(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = GET(s, "/hello.txt");
	ok(&r);
	outeq(&r, HELLO, sizeof(HELLO) - 1);
}

void
TestDownloadSizes(void)
{
	size_t sizes[] = {0, 1, 4095, 4096, 65537, 5 << 20};
	struct server s = httpserver(AF_INET, 0);
	for (size_t i = 0; i < 6; i++) {
		struct result r = run(ARGS("-q", "-o", "out", url(&s,
		    fmt("/bytes/%zu", sizes[i]))), NULL);
		ok(&r);
		unsigned char *p = pattern(sizes[i]);
		fileeq("out", p, sizes[i]);
		free(p);
		result_free(&r);
	}
}

void
TestOverwriteExisting(void)
{
	struct server s = httpserver(AF_INET, 0);
	char p[10000];
	memset(p, 'x', sizeof(p));
	putfile("out", p, sizeof(p), 0644);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	fileeq("out", HELLO, sizeof(HELLO) - 1);
}

void
TestOutputIntoDirectory(void)
{
	struct server s = httpserver(AF_INET, 0);
	CHECK(mkdir("sub", 0755) == 0);
	struct result r = run(ARGS("-q", "-o", "sub", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	fileeq("sub/hello.txt", HELLO, sizeof(HELLO) - 1);
}

void
TestMtimeFromLastModified(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct stat st;
	struct result r = run(ARGS("-q", url(&s, "/hello.txt")), NULL);
	ok(&r);
	CHECK(stat("hello.txt", &st) == 0 && st.st_mtime == MODTIME);
	r = run(ARGS("-q", "-n", url(&s, "/hello.txt")), NULL);
	ok(&r);
	CHECK(stat("hello.txt", &st) == 0 && st.st_mtime != MODTIME);
}

void
TestHTTPErrors(void)
{
	int codes[] = {400, 403, 404, 500, 503};
	struct server s = httpserver(AF_INET, 0);
	for (size_t i = 0; i < 5; i++) {
		struct result r = run(ARGS("-q", "-o", "out", url(&s,
		    fmt("/status/%d", codes[i]))), NULL);
		bad(&r);
		nofile("out");
		if (codes[i] == 404)
			errhas(&r, "Not Found");
		result_free(&r);
	}
}

void
TestRedirects(void)
{
	int codes[] = {301, 302, 303, 307, 308};
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/redirect/3")),
	    NULL);
	ok(&r);
	fileeq("out", HELLO, sizeof(HELLO) - 1);
	for (int i = 0; i < 5; i++) {
		r = run(ARGS("-q", "-o", "out", url(&s,
		    fmt("/redirect-code/%d", codes[i]))), NULL);
		ok(&r);
	}
}

void
TestRedirectLoopGivesUp(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = GET(s, "/loop");
	bad(&r);
	CHECK(request_count(&s) <= 25);
}

void
TestNoRedirectFlag(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-A", "-o", "out", url(&s,
	    "/redirect/0")), NULL);
	bad(&r);
}

void
TestChunked(void)
{
	struct server s = httpserver(AF_INET, 0);
	char want[451];
	for (int i = 0; i < 50; i++)
		snprintf(want + i * 9, 10, "chunk %02d\n", i);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/chunked")),
	    NULL);
	ok(&r);
	fileeq("out", want, 450);
}

void
TestRequestHeaders(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-o", "-",
	    "--user-agent=fetch-test/1.0", "--referer=http://example.org/ref",
	    url(&s, "/hello.txt?a=1&b=2")), NULL);
	ok(&r);
	char *q = requests(&s);
	CHECK(strstr(q, "User-Agent: fetch-test/1.0\r\n"));
	CHECK(strstr(q, "Referer: http://example.org/ref\r\n"));
	CHECK(strstr(q, "/hello.txt?a=1&b=2 HTTP/"));
	free(q);
}

void
TestFragmentNotSent(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = GET(s, "/hello.txt#frag");
	ok(&r);
	char *q = requests(&s);
	CHECK(strchr(q, '#') == NULL);
	free(q);
}

void
TestBasicAuth(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = GET(s, "/basic");
	bad(&r);
	r = run(ARGS("-q", "-o", "-",
	    fmt("http://alice:s3cret@127.0.0.1:%u/basic", s.port)), NULL);
	ok(&r);
	outeq(&r, "authorized\n", 11);
	r = run(ARGS("-q", "-o", "-", url(&s, "/basic")),
	    ARGS("HTTP_AUTH=basic:*:alice:s3cret"));
	ok(&r);
	r = run(ARGS("-q", "-o", "-",
	    fmt("http://alice:wrong@127.0.0.1:%u/basic", s.port)), NULL);
	bad(&r);
}

void
TestSizeOnly(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-s", url(&s, "/bytes/12345")), NULL);
	ok(&r);
	outeq(&r, "12345\n", 6);
	nofile("12345");
}

void
TestExpectedSize(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-S", "100", "-o", "out", url(&s,
	    "/bytes/100")), NULL);
	ok(&r);
	r = run(ARGS("-q", "-S", "99", "-o", "out", url(&s, "/bytes/100")),
	    NULL);
	bad(&r);
	errhas(&r, "size mismatch");
}

void
TestIfModifiedSince(void)
{
	struct server s = httpserver(AF_INET, 0);
	putfile("ref", "", 0, 0644);
	mtime("ref", MODTIME + 3600);
	struct result r = run(ARGS("-q", "-i", "ref", "-o", "out", url(&s,
	    "/hello.txt")), NULL);
	ok(&r);
	nofile("out");
	CHECK(strstr(requests(&s), "If-Modified-Since:"));
	mtime("ref", MODTIME - 3600);
	r = run(ARGS("-q", "-i", "ref", "-o", "out", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	fileeq("out", HELLO, sizeof(HELLO) - 1);
}

void
TestRestart(void)
{
	struct server s = httpserver(AF_INET, 0);
	unsigned char *p = pattern(100000);
	putfile("out", p, 40000, 0644);
	mtime("out", MODTIME);
	struct result r = run(ARGS("-q", "-r", "-o", "out", url(&s,
	    "/bytes/100000")), NULL);
	ok(&r);
	CHECK(strstr(requests(&s), "Range: bytes=40000-\r\n"));
	fileeq("out", p, 100000);
	free(p);
}

void
TestMirrorSkipsUpToDate(void)
{
	struct server s = httpserver(AF_INET, 0);
	for (int i = 0; i < 2; i++) {
		struct result r = run(ARGS("-q", "-m", "-o", "out", url(&s,
		    "/bytes/500")), NULL);
		ok(&r);
	}
	unsigned char *p = pattern(500);
	fileeq("out", p, 500);
	free(p);
}

void
TestMultipleURLs(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", url(&s, "/hello.txt"), url(&s,
	    "/bytes/10")), NULL);
	ok(&r);
	fileeq("hello.txt", HELLO, sizeof(HELLO) - 1);
	unsigned char *p = pattern(10);
	fileeq("10", p, 10);
	free(p);
}

void
TestTimeout(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-T", "1", "-o", "out", url(&s,
	    "/delay/10")), NULL);
	bad(&r);
	CHECK(r.seconds < 6);
}
