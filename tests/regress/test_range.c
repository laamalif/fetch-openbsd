/* ISC: see LICENSE. Resume position and identity assertions. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
static struct result
resume(const char *cr)
{
	char *p = fmt("HTTP/1.1 206 Partial Content\r\nContent-Range: %s\r\n"
	    "Content-Length: 7\r\nConnection: close\r\n\r\ndefghij", cr);
	struct server s = rawserver(p, strlen(p), 0);
	putfile("out", "abc", 3, 0644);
	return run(ARGS("-q", "-r", "-F", "-o", "out", url(&s, "/f")), NULL);
}

void
TestResumeWellFormedRange(void)
{
	struct result r = resume("bytes 3-9/10");
	ok(&r);
	fileeq("out", "abcdefghij", 10);
}

void
TestResumeMalformedRangeNeverCorrupts(void)
{
	const char *a[] = {"garbage", "bytes 3-9", "bytes 3-9/",
	    "bytes -3-9/10", "bytes 9-3/10", "bytes 3-9/5",
	    "bytes 3-18446744073709551625/18446744073709551626",
	    "bytes 18446744073709551619-9/10",
	    "bytes 3-9/99999999999999999999999"};
	for (int i = 0; i < 9; i++) {
		struct result r = resume(a[i]);
		CHECK(!r.sig);
		size_t len;
		char *b = getfile("out", &len);
		CHECK(len != 7 || memcmp(b, "defghij", 7));
		if (!r.code)
			CHECK(len == 10 && !memcmp(b, "abcdefghij", 10));
		if (strstr(a[i], "18446744073709551"))
			CHECK(r.code != 0);
		free(b);
	}
}

void
TestResumeThroughSymlink(void)
{
	struct server s = httpserver(AF_INET, 0);
	unsigned char *p = pattern(5000);
	putfile("real", p, 2000, 0644);
	mtime("real", MODTIME);
	CHECK(symlink("real", "out") == 0);
	struct result r = run(ARGS("-q", "-r", "-o", "out", url(&s,
	    "/bytes/5000")), NULL);
	ok(&r);
	fileeq("real", p, 5000);
	struct stat st;
	CHECK(lstat("out", &st) == 0 && S_ISLNK(st.st_mode));
	free(p);
}

void
TestPlainDownloadReplacesSymlink(void)
{
	struct server s = httpserver(AF_INET, 0);
	putfile("real", "precious", 8, 0644);
	CHECK(symlink("real", "out") == 0);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	fileeq("real", "precious", 8);
	struct stat st;
	CHECK(lstat("out", &st) == 0 && !S_ISLNK(st.st_mode));
}

static void
readonly(int complete)
{
	if (geteuid() == 0)
		skip("root bypasses permissions");
	struct server s = httpserver(AF_INET, 0);
	unsigned char *p = pattern(3000);
	putfile("out", p, complete ? 3000 : 1000, 0444);
	mtime("out", MODTIME);
	struct result r = run(ARGS("-q", "-r", "-o", "out", url(&s,
	    "/bytes/3000")), NULL);
	if (complete)
		ok(&r);
	else {
		bad(&r);
		errhas(&r, "out");
	}
	fileeq("out", p, complete ? 3000 : 1000);
	free(p);
}

void
TestResumeCompleteReadOnlyFile(void)
{
	readonly(1);
}

void
TestResumePartialReadOnlyFileFails(void)
{
	readonly(0);
}

void
TestResumeTargetIsTheMeasuredFile(void)
{
	putfile("out", "abc", 3, 0644);
	putfile("other", "untouched-and-much-longer", 24, 0644);
	unsigned short port;
	int fd = listener(AF_INET, &port);
	CHECK(fd >= 0);
	pid_t p = child();
	if (!p) {
		int c = accept(fd, NULL, NULL);
		CHECK(c >= 0);
		char b[4096];
		do {
			line(c, b, sizeof(b));
		} while (*b && strcmp(b, "\r\n"));
		CHECK(unlink("out") == 0);
		CHECK(symlink("other", "out") == 0);
		const char *r = "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes "
		    "3-9/10\r\nContent-Length: 7\r\nConnection: close\r\n"
		    "\r\ndefghij";
		CHECK(writeall(c, r, strlen(r)) == 0);
		close(c);
		close(fd);
		_exit(0);
	}
	close(fd);
	struct result r = run(ARGS("-q", "-r", "-F", "-o", "out",
	    fmt("http://127.0.0.1:%u/f", port)), NULL);
	CHECK(!r.sig);
	reap(p);
	fileeq("other", "untouched-and-much-longer", 24);
}
