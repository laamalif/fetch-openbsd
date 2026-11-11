/* ISC: FTP black-box fixtures */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "harness.h"

static int never_dial, other_peer;
static const char *pasv_host = "127,0,0,1";

struct ftp {
	unsigned short port;
	pid_t pid;
};

static void
reply(int fd, const char *s)
{
	CHECK(writeall(fd, s, strlen(s)) == 0);
	CHECK(writeall(fd, "\r\n", 2) == 0);
}

static void
serve(int fd, const char *name, const unsigned char *data, size_t len,
    int logfd)
{
	char buf[4096], cwd[4096] = "/", *arg, *file, *s;
	struct sockaddr_in active;
	unsigned short port;
	unsigned int a, b, c, d, p, q;
	size_t rest = 0;
	int pasv = -1, dc;

	memset(&active, 0, sizeof(active));
	active.sin_family = AF_INET;
	reply(fd, "220 fake ftp ready");
	for (;;) {
		line(fd, buf, sizeof(buf));
		if (buf[0] == '\0')
			break;
		CHECK(writeall(logfd, buf, strlen(buf)) == 0);
		buf[strcspn(buf, "\r\n")] = '\0';
		arg = strchr(buf, ' ');
		if (arg != NULL)
			*arg++ = '\0';
		else
			arg = buf + strlen(buf);
		file = fmt("%s%s%s", cwd,
		    cwd[strlen(cwd) - 1] == '/' ? "" : "/", arg);
		if (strcasecmp(buf, "USER") == 0)
			reply(fd, "331 password please");
		else if (strcasecmp(buf, "PASS") == 0)
			reply(fd, strcmp(arg, "bad") == 0 ?
			    "530 login incorrect" : "230 logged in");
		else if (strcasecmp(buf, "PWD") == 0) {
			s = fmt("257 \"%s\"", cwd);
			reply(fd, s);
			free(s);
		} else if (strcasecmp(buf, "CWD") == 0) {
			CHECK(strlen(file) < sizeof(cwd));
			memcpy(cwd, file, strlen(file) + 1);
			reply(fd, "250 ok");
		} else if (strcasecmp(buf, "CDUP") == 0) {
			s = strrchr(cwd, '/');
			CHECK(s != NULL);
			if (s == cwd)
				s[1] = '\0';
			else
				*s = '\0';
			reply(fd, "250 ok");
		} else if (strcasecmp(buf, "TYPE") == 0 ||
		    strcasecmp(buf, "MODE") == 0)
			reply(fd, "200 ok");
		else if (strcasecmp(buf, "SIZE") == 0 ||
		    strcasecmp(buf, "MDTM") == 0) {
			if (name == NULL || strcmp(file, name) != 0)
				reply(fd, "550 no such file");
			else if (strcasecmp(buf, "MDTM") == 0)
				reply(fd, "213 20200102030405");
			else {
				s = fmt("213 %zu", len);
				reply(fd, s);
				free(s);
			}
		} else if (strcasecmp(buf, "EPSV") == 0 ||
		    strcasecmp(buf, "PASV") == 0) {
			if (pasv != -1)
				close(pasv);
			pasv = listener(AF_INET, &port);
			if (strcasecmp(buf, "EPSV") == 0)
				s = fmt("229 Entering Extended Passive Mode (|||%u|)",
				    port);
			else
				s = fmt("227 Entering Passive Mode (%s,%u,%u)",
				    pasv_host, port / 256, port % 256);
			reply(fd, s);
			free(s);
		} else if (strcasecmp(buf, "EPRT") == 0) {
			char host[64];
			CHECK(sscanf(arg, "|1|%63[^|]|%u|", host, &p) == 2);
			CHECK(p > 0 && p <= 65535);
			CHECK(inet_pton(AF_INET, host, &active.sin_addr) == 1);
			active.sin_port = htons(p);
			reply(fd, "200 ok");
		} else if (strcasecmp(buf, "PORT") == 0) {
			CHECK(sscanf(arg, "%u,%u,%u,%u,%u,%u", &a, &b, &c,
			    &d, &p, &q) == 6);
			CHECK(a <= 255 && b <= 255 && c <= 255 && d <= 255 &&
			    p <= 255 && q <= 255);
			active.sin_addr.s_addr = htonl(a << 24 | b << 16 | c << 8 | d);
			active.sin_port = htons(p * 256 + q);
			reply(fd, "200 ok");
		} else if (strcasecmp(buf, "REST") == 0) {
			rest = strtoul(arg, NULL, 10);
			reply(fd, "350 restarting");
		} else if (strcasecmp(buf, "RETR") == 0) {
			if (name == NULL || strcmp(file, name) != 0)
				reply(fd, "550 no such file");
			else {
				reply(fd, "150 opening data connection");
				if (pasv != -1) {
					dc = accept(pasv, NULL, NULL);
					close(pasv);
					pasv = -1;
				} else {
					if (never_dial) {
						/* Keep control open until the client times out. */
						while (read(fd, buf, sizeof(buf)) > 0)
							;
						free(file);
						return;
					}
					dc = socket(AF_INET, SOCK_STREAM, 0);
					CHECK(dc != -1);
					if (other_peer) {
						struct sockaddr_in local = active;
						local.sin_port = 0;
						CHECK(inet_pton(AF_INET, "127.0.0.2",
						    &local.sin_addr) == 1);
						CHECK(bind(dc, (struct sockaddr *)&local,
						    sizeof(local)) == 0);
					}
					CHECK(connect(dc, (struct sockaddr *)&active,
					    sizeof(active)) == 0);
				}
				CHECK(dc != -1);
				if (rest > len)
					rest = len;
				if (other_peer) {
					/* Rejection may close the data socket immediately. */
					(void)writeall(dc, data + rest, len - rest);
					close(dc);
					(void)writeall(fd, "226 transfer complete\r\n", 23);
					free(file);
					return;
				}
				CHECK(writeall(dc, data + rest, len - rest) == 0);
				close(dc);
				rest = 0;
				reply(fd, "226 transfer complete");
			}
		} else if (strcasecmp(buf, "QUIT") == 0) {
			reply(fd, "221 bye");
			free(file);
			break;
		} else
			reply(fd, "502 not implemented");
		free(file);
	}
	if (pasv != -1)
		close(pasv);
}

static struct ftp
newftp(const char *name, const unsigned char *data, size_t len, int sessions)
{
	struct ftp f;
	int ln, fd, logfd, i;

	ln = listener(AF_INET, &f.port);
	logfd = open("ftp.log", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(logfd != -1);
	f.pid = child();
	if (f.pid == 0) {
		for (i = 0; i < sessions; i++) {
			fd = accept(ln, NULL, NULL);
			CHECK(fd != -1);
			serve(fd, name, data, len, logfd);
			close(fd);
		}
		close(logfd);
		close(ln);
		_exit(0);
	}
	close(ln);
	close(logfd);
	return f;
}

static void
command(const char *want)
{
	char *log;
	size_t len;

	log = getfile("ftp.log", &len);
	CHECK(strstr(log, want) != NULL);
	free(log);
}

void
TestFTPPassive(void)
{
	unsigned char *data = pattern(200000);
	struct ftp f = newftp("/pub/file.bin", data, 200000, 1);
	char *url = fmt("ftp://127.0.0.1:%u/pub/file.bin", f.port);
	struct result r = run(ARGS("-q", "-o", "out", url), NULL);

	ok(&r);
	reap(f.pid);
	fileeq("out", data, 200000);
	command("USER anonymous");
	result_free(&r);
	free(url);
	free(data);
}

void
TestFTPActive(void)
{
	unsigned char *data = pattern(5000);
	struct ftp f = newftp("/file.bin", data, 5000, 1);
	char *url = fmt("ftp://127.0.0.1:%u/file.bin", f.port), *log;
	size_t len;
	struct result r = run(ARGS("-q", "--no-passive", "-o", "out", url), NULL);

	ok(&r);
	reap(f.pid);
	fileeq("out", data, 5000);
	log = getfile("ftp.log", &len);
	CHECK(strstr(log, "PORT") != NULL || strstr(log, "EPRT") != NULL);
	free(log);
	result_free(&r);
	free(url);
	free(data);
}

void
TestFTPAuth(void)
{
	struct ftp f = newftp("/f", (const unsigned char *)"x", 1, 2);
	char *url = fmt("ftp://bob:pw@127.0.0.1:%u/f", f.port);
	struct result r = run(ARGS("-q", "-o", "out", url), NULL);

	ok(&r);
	command("USER bob");
	command("PASS pw");
	result_free(&r);
	free(url);
	url = fmt("ftp://bob:bad@127.0.0.1:%u/f", f.port);
	r = run(ARGS("-q", "-o", "out", url), NULL);
	bad(&r);
	reap(f.pid);
	result_free(&r);
	free(url);
}

void
TestFTPMissingFile(void)
{
	struct ftp f = newftp(NULL, NULL, 0, 1);
	char *url = fmt("ftp://127.0.0.1:%u/nope", f.port);
	struct result r = run(ARGS("-q", "-o", "out", url), NULL);

	bad(&r);
	reap(f.pid);
	nofile("out");
	result_free(&r);
	free(url);
}

void
TestFTPRestart(void)
{
	unsigned char *data = pattern(50000);
	struct ftp f = newftp("/f", data, 50000, 2);
	char *url = fmt("ftp://127.0.0.1:%u/f", f.port);
	struct result r = run(ARGS("-q", "-o", "out", url), NULL);

	ok(&r);
	fileeq("out", data, 50000);
	result_free(&r);
	putfile("out", data, 20000, 0644);
	mtime("out", MODTIME);
	r = run(ARGS("-q", "-r", "-o", "out", url), NULL);
	ok(&r);
	reap(f.pid);
	command("REST 20000");
	fileeq("out", data, 50000);
	result_free(&r);
	free(url);
	free(data);
}

void
TestFTPActiveHonoursTimeout(void)
{
	unsigned char *data = pattern(100);
	struct ftp f;
	struct result r;
	char *url;

	never_dial = 1;
	f = newftp("/f", data, 100, 1);
	url = fmt("ftp://127.0.0.1:%u/f", f.port);
	r = run(ARGS("-q", "-T", "2", "--no-passive", "-o", "out", url), NULL);
	bad(&r);
	CHECK(r.seconds <= 8);
	reap(f.pid);
	result_free(&r);
	free(url);
	free(data);
}

void
TestFTPPassiveIgnoresAdvertisedAddress(void)
{
	unsigned char *data = pattern(3000);
	struct ftp f;
	struct result r;
	char *url;

	pasv_host = "192,0,2,1";
	f = newftp("/f", data, 3000, 1);
	url = fmt("ftp://127.0.0.1:%u/f", f.port);
	r = run(ARGS("-q", "-T", "5", "-o", "out", url), NULL);
	ok(&r);
	fileeq("out", data, 3000);
	reap(f.pid);
	result_free(&r);
	free(url);
	free(data);
}

void
TestFTPActiveRejectsOtherPeer(void)
{
	struct sockaddr_in local;
	unsigned char *data;
	struct ftp f;
	struct result r;
	char *url;
	int fd;

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	CHECK(inet_pton(AF_INET, "127.0.0.2", &local.sin_addr) == 1);
	fd = socket(AF_INET, SOCK_STREAM, 0);
	CHECK(fd != -1);
	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) == -1 ||
	    listen(fd, 1) == -1) {
		close(fd);
		skip("no 127.0.0.2 on lo0");
		return;
	}
	close(fd);
	other_peer = 1;
	data = pattern(100);
	f = newftp("/f", data, 100, 1);
	url = fmt("ftp://127.0.0.1:%u/f", f.port);
	r = run(ARGS("-q", "-T", "3", "--no-passive", "-o", "out", url), NULL);
	bad(&r);
	nofile("out");
	reap(f.pid);
	result_free(&r);
	free(url);
	free(data);
}

/* Shared only with the verbose-output cases. */
void
verbose_ftp_passwords(void)
{
	struct ftp f = newftp("/f", (const unsigned char *)"data", 4, 2);
	char *url = fmt("ftp://bob:ftppw@127.0.0.1:%u/f", f.port);
	struct result r = run(ARGS("-vvv", "-o", "-", url), NULL);

	ok(&r);
	CHECK(strstr(r.err, "ftppw") == NULL);
	command("PASS ftppw");
	result_free(&r);
	free(url);
	url = fmt("ftp://127.0.0.1:%u/f", f.port);
	r = run(ARGS("-vvv", "-o", "-", url),
	    ARGS("FTP_LOGIN=bob", "FTP_PASSWORD=envpw"));
	ok(&r);
	CHECK(strstr(r.err, "envpw") == NULL);
	reap(f.pid);
	result_free(&r);
	free(url);
}
