/* ISC: see LICENSE. Diagnostics must not alter bodies or expose passwords. */
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "server.h"
void
TestRedirectLocationIsEscapedAndRedacted(void)
{
	struct server s = redirectserver("http://bob:hunter2@127.0.0.1:1/a\033[2J\033]0;pwned\007", 0);
	struct result r = run(ARGS("-v", "-o", "out", url(&s, "/x")), NULL);
	CHECK(r.sig == 0);
	CHECK(!strchr(r.err, '\033') && !strchr(r.err, '\007'));
	CHECK(!strstr(r.err, "hunter2"));
	errhas(&r, "\\033[2J");
}

void
TestErrorMessageRedactsPassword(void)
{
	struct result r = run(ARGS("-q", "-o", "out",
	    "http://alice:s3cret@127.0.0.1:1/x"), NULL);
	bad(&r);
	CHECK(!strstr(r.err, "s3cret"));
	errhas(&r, "127.0.0.1:1/x");
}

void
TestBodyIsNotEscaped(void)
{
	const char p[] = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"
	    "\033[2J\007\000";
	struct server s = rawserver(p, sizeof(p) - 1, 0);
	struct result r = run(ARGS("-q", "-o", "-", url(&s, "/x")), NULL);
	ok(&r);
	outeq(&r, "\033[2J\007\000", 6);
}

void
TestNumericOptionRanges(void)
{
	const char *a[][2] = {{"-T", "-5"}, {"-T", "4294967296"}, {"-T",
	    "99999999999999999999"}, {"-T", "1.5"}, {"-w", "-5"}, {"-w",
	    "4294967296"}, {"-w", "99999999999999999999"}, {"-B", "-5"},
	    {"-B", "99999999999999999999"}, {"-B", "0x10"}, {"-S", "-1"},
	    {"-S", "99999999999999999999"}};
	for (size_t i = 0; i < 12; i++) {
		struct result r = run(ARGS("-q", "-o", "-", a[i][0], a[i][1],
		    "http://127.0.0.1:1/"), NULL);
		CHECK(r.sig == 0 && r.code == 1);
		CHECK(strstr(r.err, fmt("(%s) is too",
		    a[i][1])) || strstr(r.err, fmt("(%s) is invalid",
		    a[i][1])));
	}
	const char *names[] = {"FTP_TIMEOUT", "HTTP_TIMEOUT"},
	    *values[] = {"-5", "99999999999999999999", "x"};
	for (int i = 0; i < 2; i++)
		for (int j = 0; j < 3; j++) {
			struct result r = run(ARGS("-q", "-o", "-",
			    "http://127.0.0.1:1/"), ARGS(fmt("%s=%s",
			    names[i], values[j])));
			CHECK(r.sig == 0);
			errhas(&r, fmt("%s (%s)", names[i], values[j]));
		}
}

void
TestRequireSizeZero(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/bytes/0")),
	    NULL);
	ok(&r);
	r = run(ARGS("-q", "-S", "0", "-o", "out", url(&s, "/bytes/0")), NULL);
	ok(&r);
	r = run(ARGS("-q", "-S", "0", "-o", "out", url(&s, "/bytes/10")), NULL);
	bad(&r);
	errhas(&r, "size mismatch");
}

void
TestHugeTimeoutStillWorks(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-T", "31536000", "-o", "-", url(&s,
	    "/hello.txt")), NULL);
	ok(&r);
	CHECK(r.seconds < 10);
}

void
TestRedirectHostCannotReachAuthPrompt(void)
{
	const char *a[] = {"http://ev\033[31mil.example/x",
	    "http://evil%1b[31m.example/x", "http://evil.example\007/x",
	    "http://[::1\033]/x", "http://evil.example.invalid/x"};
	/* the last host is a real lookup, which fails only if the resolver answers */
	int dns = resolver_answers();
	for (int i = 0; i < 5; i++) {
		if (i == 4 && !dns)
			continue;
		struct server s = redirectserver(a[i], 0);
		struct result r = run(ARGS("-o", "-", url(&s, "/")), NULL);
		bad(&r);
		CHECK(!strstr(r.err,
		    "Authentication required") && !strstr(r.err, "Login:"));
		CHECK(!strchr(r.err, '\033') && !strchr(r.err, '\007'));
	}
}
