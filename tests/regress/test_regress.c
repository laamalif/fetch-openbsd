/* ISC: see LICENSE. Authentication origin and final output errors. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
void
TestRedirectCredentialsStayInOrigin(void)
{
	for (int secure = 0; secure < 2; secure++) {
		struct server target = httpserver(AF_INET, 0),
		    src = redirectserver(url(&target, "/challenge"), secure);
		struct result r = run(ARGS("-q", "-o", "-",
		    fmt("--ca-cert=%s/certs/server.pem", suitedir),
		    fmt("%s://alice:s3cret@127.0.0.1:%u/x",
		    secure ? "https" : "http", src.port)), NULL);
		bad(&r);
		CHECK(!strstr(requests(&target), "Authorization:"));
	}
	struct server target = httpserver(AF_INET, 0),
	    src = redirectserver(fmt("http://alice:s3cret@127.0.0.1:%u/challenge", target.port), 0);
	struct result r = run(ARGS("-q", "-o", "-", url(&src, "/x")), NULL);
	ok(&r);
	outeq(&r, "authed\n", 7);
}
/* A dedicated two-stage fixture keeps both redirect forms on one origin. */
void
TestRedirectCredentialsSameOrigin(void)
{
	for (int absolute = 0; absolute < 2; absolute++) {
		unsigned short port;
		int fd = listener(AF_INET, &port);
		CHECK(fd >= 0);
		pid_t p = child();
		if (!p) {
			for (int n = 0; n < 3; n++) {
				int c = accept(fd, NULL, NULL);
				CHECK(c >= 0);
				char b[4096];
				int auth = 0;
				do {
					line(c, b, sizeof(b));
					if (strstr(b,
					    "Authorization: Basic YWxpY2U6czNjcmV0"))
						auth = 1;
				} while (*b && strcmp(b, "\r\n"));
				char *r;
				if (n == 0)
					r = fmt("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: "
					    "0\r\nConnection: close\r\n\r\n",
					    absolute ? fmt("http://127.0.0.1:%u/basic", port) : "/basic");
				else if (!auth)
					r = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic "
					    "realm=\"x\"\r\nContent-Length: 0\r\nConnection: "
					    "close\r\n\r\n";
				else
					r = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: "
					    "close\r\n\r\nauthed\n";
				CHECK(writeall(c, r, strlen(r)) == 0);
				close(c);
				if (n && auth) {
					close(fd);
					_exit(0);
				}
			} _exit(2);
		}
	close(fd);
		struct result r = run(ARGS("-q", "-o", "-",
		    fmt("http://alice:s3cret@127.0.0.1:%u/hop", port)), NULL);
		ok(&r);
		outeq(&r, "authed\n", 7);
		reap(p);
	}
}

void
TestPassivePortrangeDefault(void)
{
	char *p = fmt("%s/../longopt-%ld", testdir, (long)getpid());
	putfile(p, "data\n", 5, 0644);
	const char *a[] = {"--passive-portrange-default", "-U"};
	for (int i = 0; i < 2; i++) {
		struct result r = run(ARGS("-q", "-o", "-", a[i],
		    fmt("file://%s", p)), NULL);
		ok(&r);
		outeq(&r, "data\n", 5);
	}
}

void
TestWriteErrorIsReported(void)
{
	struct server s = httpserver(AF_INET, 0);
	for (int n = 0; n < 2; n++) {
		unlink("out");
		run_limit = 1;
		struct result r = run(n ? ARGS("-q", "-n", "-o", "out",
		    url(&s, "/bytes/5000")) : ARGS("-q", "-o", "out", url(&s,
		    "/bytes/5000")), NULL);
		bad(&r);
		struct stat st;
		if (!stat("out", &st))
			CHECK(st.st_size == 0);
		putfile("out", "precious\n", 9, 0644);
		r = run(n ? ARGS("-q", "-n", "-o", "out", url(&s,
		    "/bytes/5000")) : ARGS("-q", "-o", "out", url(&s,
		    "/bytes/5000")), NULL);
		bad(&r);
		fileeq("out", "precious\n", 9);
		CHECK(entries(".") == 1);
	}
	run_limit = 0;
}

void
TestWriteErrorToStdout(void)
{
	struct server s = httpserver(AF_INET, 0);
	run_limit = 1;
	run_sink = "sink";
	struct result r = run(ARGS("-q", "-o", "-", url(&s, "/bytes/5000")),
	    NULL);
	bad(&r);
	run_limit = 0;
	run_sink = NULL;
}
