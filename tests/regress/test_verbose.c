/* ISC: verbose-output tests */
#include <sys/socket.h>
#include <netinet/in.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "harness.h"

void verbose_ftp_passwords(void);

struct verbose_server {
	unsigned short port;
	pid_t pid;
};

/* Each fixture serves one successful request, with any preceding challenge. */
static struct verbose_server
verbose_server(int challenge)
{
	struct verbose_server s;
	int ln, fd, logfd, authenticated;
	char buf[4096], *value;
	const char *response;

	ln = listener(AF_INET, &s.port);
	logfd = open("verbose.auth", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(logfd != -1);
	s.pid = child();
	if (s.pid == 0) {
		for (;;) {
			fd = accept(ln, NULL, NULL);
			CHECK(fd != -1);
			authenticated = 0;
			for (;;) {
				line(fd, buf, sizeof(buf));
				CHECK(buf[0] != '\0');
				if (strcmp(buf, "\r\n") == 0)
					break;
				if (strncasecmp(buf, "Authorization:", 14) != 0)
					continue;
				value = buf + 14;
				while (*value == ' ' || *value == '\t')
					value++;
				value[strcspn(value, "\r\n")] = '\0';
				CHECK(writeall(logfd, value, strlen(value)) == 0);
				CHECK(writeall(logfd, "\n", 1) == 0);
				authenticated = strcmp(value,
				    "Basic YWxpY2U6czNjcmV0") == 0;
			}
			if (!challenge)
				response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n"
				    "Connection: close\r\n\r\n" HELLO;
			else if (authenticated)
				response = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n"
				    "Connection: close\r\n\r\nauthed\n";
			else
				response = "HTTP/1.1 401 Unauthorized\r\n"
				    "WWW-Authenticate: Basic realm=\"x\"\r\n"
				    "Content-Length: 3\r\nConnection: close\r\n\r\nno\n";
			CHECK(writeall(fd, response, strlen(response)) == 0);
			close(fd);
			if (!challenge || authenticated)
				break;
		}
		close(logfd);
		close(ln);
		_exit(0);
	}
	close(logfd);
	close(ln);
	return s;
}

void
TestVerboseNeverShowsCredentials(void)
{
	const char *levels[] = {"-v", "-vv", "-vvv"};
	struct verbose_server s;
	struct result r;
	char *url;
	size_t i;
	int source;

	for (i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
		for (source = 0; source < 2; source++) {
			s = verbose_server(1);
			url = fmt("http://%s127.0.0.1:%u/x",
			    source == 0 ? "alice:s3cret@" : "", s.port);
			r = run(ARGS(levels[i], "-o", "-", url), source == 0 ?
			    NULL : ARGS("HTTP_AUTH=basic:*:alice:s3cret"));
			ok(&r);
			outeq(&r, "authed\n", 7);
			CHECK(strstr(r.err, "s3cret") == NULL);
			CHECK(strstr(r.err, "YWxpY2U6czNjcmV0") == NULL);
			if (i == 2)
				errhas(&r, "Authorization: <hidden>");
			reap(s.pid);
			result_free(&r);
			free(url);
		}
	}
}

void
TestVerboseStillAuthenticates(void)
{
	struct verbose_server s = verbose_server(1);
	char *url = fmt("http://alice:s3cret@127.0.0.1:%u/x", s.port);
	const char expected[] = "Basic YWxpY2U6czNjcmV0\n";
	struct result r = run(ARGS("-vvv", "-o", "-", url), NULL);

	ok(&r);
	reap(s.pid);
	fileeq("verbose.auth", expected, sizeof(expected) - 1);
	result_free(&r);
	free(url);
}

void
TestVerboseKeepsOtherHeaders(void)
{
	struct verbose_server s = verbose_server(0);
	char *url = fmt("http://127.0.0.1:%u/hello.txt", s.port);
	struct result r = run(ARGS("-vvv", "-o", "-", "--user-agent=probe/1",
	    url), NULL);

	ok(&r);
	errhas(&r, "GET /hello.txt HTTP/1.1");
	errhas(&r, "User-Agent: probe/1");
	errhas(&r, "Host: ");
	reap(s.pid);
	result_free(&r);
	free(url);
}

void
TestVerboseNeverShowsNetrcOrFTPPassword(void)
{
	const char netrc[] = "machine 127.0.0.1 login alice password s3cret\n";
	struct verbose_server s = verbose_server(1);
	char *url = fmt("http://127.0.0.1:%u/x", s.port);
	char *env = fmt("NETRC=%s/netrc", testdir);
	struct result r;

	putfile("netrc", netrc, sizeof(netrc) - 1, 0600);
	r = run(ARGS("-vvv", "-o", "-", url), ARGS(env));
	ok(&r);
	CHECK(strstr(r.err, "s3cret") == NULL);
	reap(s.pid);
	result_free(&r);
	free(url);
	free(env);
	verbose_ftp_passwords();
}
