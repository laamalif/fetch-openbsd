/* ISC: see LICENSE. Observable filesystem and sandbox behavior. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
void
TestRedirectToFileNotFollowed(void)
{
	char *secret = fmt("%s/../secret-%ld", testdir, (long)getpid());
	putfile(secret, "TOP-SECRET\n", 11, 0600);
	const char *prefix[] = {"file://", "file://localhost", "file:"};
	for (int i = 0; i < 3; i++) {
		struct server s = redirectserver(fmt("%s%s", prefix[i],
		    secret), 0);
		struct result r = run(ARGS("-q", "-o", "out", url(&s, "/x")),
		    NULL);
		bad(&r);
		nofile("out");
		CHECK(!strstr(r.out, "TOP-SECRET") && !strstr(r.err,
		    "TOP-SECRET"));
	}
}

void
TestStdoutWritesNoFiles(void)
{
	struct server s = httpserver(AF_INET, 0);
	struct result r = run(ARGS("-q", "-o", "-", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	outeq(&r, HELLO, sizeof(HELLO) - 1);
	CHECK(entries(".") == 0);
}

void
TestOutputElsewhere(void)
{
	struct server s = httpserver(AF_INET, 0);
	char *other = fmt("%s/../elsewhere-%ld", testdir, (long)getpid());
	CHECK(mkdir(other, 0700) == 0);
	struct result r = run(ARGS("-q", "-o", fmt("%s/a", other), url(&s,
	    "/hello.txt")), NULL);
	ok(&r);
	r = run(ARGS("-q", "-o", other, url(&s, "/hello.txt")), NULL);
	ok(&r);
	fileeq(fmt("%s/a", other), HELLO, sizeof(HELLO) - 1);
	fileeq(fmt("%s/hello.txt", other), HELLO, sizeof(HELLO) - 1);
}

void
TestIfModifiedSinceFile(void)
{
	struct server s = httpserver(AF_INET, 0);
	char *ref = fmt("%s/../ref-%ld", testdir, (long)getpid());
	putfile(ref, "", 0, 0644);
	mtime(ref, MODTIME + 366 * 86400);
	struct result r = run(ARGS("-q", "-i", ref, "-o", "out", url(&s,
	    "/hello.txt")), NULL);
	CHECK(!r.sig);
	nofile("out");
	if (!r.code)
		CHECK(r.outlen == 0);
	CHECK(strstr(requests(&s), "If-Modified-Since:"));
}

void
TestResumeMtimeMismatch(void)
{
	struct server s = httpserver(AF_INET, 0);
	unsigned char *p = pattern(100000);
	int sizes[] = {0, 1000};
	for (int i = 0; i < 2; i++) {
		putfile("out", p, sizes[i], 0644);
		mtime("out", MODTIME + 86400);
		struct result r = run(ARGS("-q", "-r", "-o", "out", url(&s,
		    "/bytes/5000")), NULL);
		ok(&r);
		fileeq("out", p, 5000);
		CHECK(entries(".") == 1);
	}
	free(p);
}

void
TestResumePreciousMismatch(void)
{
	struct server s = httpserver(AF_INET, 0);
	putfile("out", "keep me", 7, 0644);
	mtime("out", MODTIME + 86400);
	struct result r = run(ARGS("-q", "-r", "-R", "-o", "out", url(&s,
	    "/bytes/5000")), NULL);
	bad(&r);
	fileeq("out", "keep me", 7);
	CHECK(entries(".") == 1);
}

void
TestReplaceKeepsModeAndLeavesNoTemp(void)
{
	struct server s = httpserver(AF_INET, 0);
	putfile("out", "old", 3, 0640);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/bytes/3000")),
	    NULL);
	ok(&r);
	struct stat st;
	CHECK(stat("out", &st) == 0 && (st.st_mode & 0777) == 0640);
	unsigned char *p = pattern(3000);
	fileeq("out", p, 3000);
	free(p);
	CHECK(entries(".") == 1);
}

void
TestDevNullUnveilsOnlyTheDevice(void)
{
	if (access("/usr/bin/ktrace", X_OK))
		skip("no ktrace");
	struct server s = httpserver(AF_INET, 0);
	char saved[4096];
	strlcpy(saved, fetchbin, sizeof(saved));
	strlcpy(fetchbin, "/usr/bin/ktrace", sizeof(fetchbin));
	struct result r = run(ARGS("-f", "kt.out", saved, "-q", "-o",
	    "/dev/null", url(&s, "/hello.txt")), NULL);
	ok(&r);
	strlcpy(fetchbin, "/usr/bin/kdump", sizeof(fetchbin));
	r = run(ARGS("-f", "kt.out"), NULL);
	strlcpy(fetchbin, saved, sizeof(fetchbin));
	if (r.code)
		skip("kdump unavailable");
	char *save, *l = strtok_r(r.out, "\n", &save);
	int in = 0, seen = 0;
	while (l) {
		if (strstr(l, "CALL  unveil("))
			in = !strstr(l, "unveil(0,0)");
		if (in && strstr(l, "NAMI")) {
			CHECK(!strstr(l, "\"/dev\""));
			if (strstr(l, "\"/dev/null\""))
				seen = 1;
		}
		if (strstr(l, "RET   unveil"))
			in = 0;
		l = strtok_r(NULL, "\n", &save);
	}
	CHECK(seen);
}
