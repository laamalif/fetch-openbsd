/* ISC: see LICENSE. Output metadata and atomic replacement regressions. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "server.h"
static mode_t
mode(const char *p)
{
	struct stat st;
	CHECK(stat(p, &st) == 0);
	return st.st_mode & 07777;
}

void
TestReplaceDropsSpecialBits(void)
{
	struct server s = httpserver(AF_INET, 0);
	const char *paths[] = {"/bytes/0", "/hello.txt"};
	for (int i = 0; i < 2; i++) {
		putfile("out", "old\n", 4, 0640);
		if (chmod("out", 07640))
			skip("cannot set special bits");
		struct result r = run(ARGS("-q", "-o", "out", url(&s,
		    paths[i])), NULL);
		ok(&r);
		CHECK(mode("out") == 0640);
	}
}

void
TestReplacementPrivateWhileDownloading(void)
{
	unsigned short port;
	int fd = listener(AF_INET, &port);
	CHECK(fd >= 0);
	putfile("out", "old\n", 4, 0644);
	pid_t p = child();
	if (!p) {
		int c = accept(fd, NULL, NULL);
		CHECK(c >= 0);
		char b[4096];
		do {
			line(c, b, sizeof(b));
		} while (*b && strcmp(b, "\r\n"));
		const char *h = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
		CHECK(writeall(c, h, strlen(h)) == 0);
		double end = monotime() + 5;
		int found = 0;
		while (monotime() < end && !found) {
			DIR *d = opendir(".");
			CHECK(d);
			struct dirent *e;
			while ((e = readdir(d))) {
				if (!strncmp(e->d_name, ".fetch.", 7)) {
					CHECK((mode(e->d_name) & 0077) == 0);
					found = 1;
				}
			}
			closedir(d);
			if (!found)
				usleep(10000);
		}
		CHECK(found);
		CHECK(writeall(c, "world", 5) == 0);
		close(c);
		close(fd);
		_exit(0);
	}
	close(fd);
	struct result r = run(ARGS("-q", "-o", "out",
	    fmt("http://127.0.0.1:%u/x", port)), NULL);
	ok(&r);
	reap(p);
	fileeq("out", "helloworld", 10);
	CHECK(mode("out") == 0644);
}

void
TestNewFileDoesNotFollowDanglingSymlink(void)
{
	struct server s = httpserver(AF_INET, 0);
	CHECK(symlink("victim", "out") == 0);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	nofile("victim");
	fileeq("out", HELLO, sizeof(HELLO) - 1);
}

void
TestResumeNewFileNoFollow(void)
{
	struct server s = httpserver(AF_INET, 0);
	const char *flags[] = {"-r", "-R"};
	for (int i = 0; i < 2; i++) {
		CHECK(symlink("victim", "out") == 0);
		struct result r = run(ARGS("-q", flags[i], "-o", "out",
		    url(&s, "/hello.txt")), NULL);
		bad(&r);
		nofile("victim");
		CHECK(unlink("out") == 0);
	}
}

void
TestNewFileModeAndNoDebris(void)
{
	struct server s = httpserver(AF_INET, 0);
	run_umask = 022;
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	CHECK(mode("out") == 0644);
	CHECK(entries(".") == 1);
}

void
TestReplaceSymlinkLeavesTarget(void)
{
	struct server s = httpserver(AF_INET, 0);
	putfile("target", "keep\n", 5, 0644);
	CHECK(symlink("target", "out") == 0);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/hello.txt")),
	    NULL);
	ok(&r);
	fileeq("target", "keep\n", 5);
}

void
TestTruncatedReplacementLeavesNoDebris(void)
{
	const char *p = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: "
	    "close\r\n\r\nshort";
	struct server s = rawserver(p, strlen(p), 0);
	putfile("out", "old\n", 4, 0644);
	struct result r = run(ARGS("-q", "-o", "out", url(&s, "/x")), NULL);
	bad(&r);
	fileeq("out", "old\n", 4);
	CHECK(entries(".") == 1);
}
