/* ISC: see LICENSE. Retry requests must agree with bytes on disk. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
static struct server
flaky(int honour)
{
	struct server s;
	int fd = listener(AF_INET, &s.port);
	CHECK(fd >= 0);
	s.url = fmt("http://127.0.0.1:%u", s.port);
	s.log = fmt("%s/../retry-%u", testdir, s.port);
	putfile(s.log, "", 0, 0600);
	s.pid = child();
	if (!s.pid) {
		for (int i = 0;; i++) {
			int c = accept(fd, NULL, NULL);
			CHECK(c >= 0);
			char b[4096];
			int ranged = 0;
			do {
				line(c, b, sizeof(b));
				record(s.log, b);
				if (strstr(b, "Range: bytes=3-"))
					ranged = 1;
			} while (*b && strcmp(b, "\r\n"));
			const char *r = i == 0 ? "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: "
			    "close\r\n\r\nabc" : honour && ranged ? "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes "
			    "3-9/10\r\nContent-Length: 7\r\nConnection: close\r\n"
			    "\r\ndefghij" : "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: "
			    "close\r\n\r\nabcdefghij";
			writeall(c, r, strlen(r));
			close(c);
		}
	}
	close(fd);
	return s;
}

void
TestAutoRetryProducesExactContent(void)
{
	for (int honour = 0; honour < 2; honour++)
		for (int exists = 0; exists < 2; exists++) {
			unlink("out");
			struct server s = flaky(honour);
			if (exists)
				putfile("out", "OLD-OLD-OLD-OLD-OLD", 19, 0644);
			struct result r = run(ARGS("-q", "-a", "-o", "out",
			    url(&s, "/f")), NULL);
			CHECK(!r.sig);
			if (!r.code)
				fileeq("out", "abcdefghij", 10);
			else if (exists)
				fileeq("out", "OLD-OLD-OLD-OLD-OLD", 19);
			CHECK(entries(".") == 1);
		}
}

void
TestAutoRetryToStdout(void)
{
	for (int honour = 0; honour < 2; honour++) {
		struct server s = flaky(honour);
		struct result r = run(ARGS("-q", "-a", "-o", "-", url(&s,
		    "/f")), NULL);
		CHECK(!r.sig);
		if (!r.code)
			outeq(&r, "abcdefghij", 10);
	}
}

void
TestAutoRetryUsesRange(void)
{
	struct server s = flaky(1);
	struct result r = run(ARGS("-q", "-a", "-o", "out", url(&s, "/f")),
	    NULL);
	ok(&r);
	CHECK(request_count(&s) == 2);
	char *log = requests(&s);
	char *second = strstr(log, "\r\n\r\n");
	CHECK(second != NULL);
	CHECK(strstr(second + 4, "Range: bytes=3-\r\n") != NULL);
	free(log);
}

void
TestAutoRetryToDevice(void)
{
	for (int honour = 1; honour >= 0; honour--) {
		struct server s = flaky(honour);
		struct result r = run(ARGS("-q", "-a", "-o", "/dev/null",
		    url(&s, "/f")), NULL);
		if (honour)
			ok(&r);
		else {
			bad(&r);
			errhas(&r, "cannot retry");
		}
	}
}
