/* ISC: see LICENSE. Test processes and fixtures never modify the source tree. */
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "harness.h"

char testdir[4096], fetchbin[4096], suitedir[4096];
mode_t run_umask = 022;
int run_limit;
const char *run_sink;
static pid_t children[512];
static size_t nchildren;
static volatile sig_atomic_t interrupted;

/* The child could not set up fetch's environment: say which step, and why. */
static void __attribute__((noreturn))
setup_failed(const char *step)
{
	dprintf(2, "harness: %s: %s\n", step, strerror(errno));
	_exit(126);
}

/* Only harness-initiated termination is an acceptable fixture signal. */
static int
cleanup(void)
{
	size_t i;
	int status, failed = 0;
	pid_t p;

	for (i = 0; i < nchildren; i++) {
		if (children[i] <= 0)
			continue;
		do {
			p = waitpid(children[i], &status, WNOHANG);
		} while (p == -1 && errno == EINTR);
		if (p == 0) {
			kill(children[i], SIGKILL);
			do {
				p = waitpid(children[i], &status, 0);
			} while (p == -1 && errno == EINTR);
			if (p > 0 && WIFSIGNALED(status) &&
			    WTERMSIG(status) == SIGKILL)
				continue;
		}
		if (p < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
			fprintf(stderr,
			    "fixture %ld failed (wait %ld, status %d)\n",
			    (long)children[i], (long)p, p < 0 ? -1 : status);
			failed = 1;
		}
	}
	nchildren = 0;
	return failed;
}

void
fail(const char *file, int ln, const char *format, ...)
{
	va_list ap;
	fprintf(stderr, "%s:%d: ", file, ln);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fputc('\n', stderr);
	cleanup();
	exit(1);
}

void
skip(const char *why)
{
	fprintf(stderr, "SKIP: %s\n", why);
	cleanup();
	exit(77);
}

void *
xmalloc(size_t n)
{
	void *p = calloc(1, n ? n : 1);
	CHECK(p != NULL);
	return p;
}

char *
fmt(const char *format, ...)
{
	va_list ap;
	char *s;
	va_start(ap, format);
	int n = vasprintf(&s, format, ap);
	va_end(ap);
	CHECK(n >= 0);
	return s;
}

int
writeall(int fd, const void *v, size_t n)
{
	const char *p = v;
	ssize_t r;
	while (n) {
		r = write(fd, p, n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		p += r;
		n -= r;
	}
	return 0;
}

int
readexact(int fd, void *v, size_t n)
{
	char *p = v;
	ssize_t r;
	while (n) {
		r = read(fd, p, n);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return -1;
		p += r;
		n -= r;
	}
	return 0;
}

void
line(int fd, char *p, size_t n)
{
	size_t i = 0;
	while (i + 1 < n) {
		if (readexact(fd, p + i, 1))
			break;
		if (p[i++] == '\n')
			break;
	}
	p[i] = 0;
}

void
putfile(const char *name, const void *data, size_t n, mode_t mode)
{
	int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, mode);
	CHECK(fd >= 0);
	CHECK(writeall(fd, data, n) == 0);
	CHECK(fchmod(fd, mode) == 0);
	CHECK(close(fd) == 0);
}

char *
getfile(const char *name, size_t *len)
{
	struct stat st;
	int fd = open(name, O_RDONLY);
	char *p;
	CHECK(fd >= 0);
	CHECK(fstat(fd, &st) == 0);
	CHECK(st.st_size >= 0 && st.st_size < 64 * 1024 * 1024);
	p = xmalloc(st.st_size + 1);
	CHECK(readexact(fd, p, st.st_size) == 0);
	CHECK(close(fd) == 0);
	if (len)
		*len = st.st_size;
	return p;
}

void
fileeq(const char *p, const void *v, size_t n)
{
	size_t z;
	char *b = getfile(p, &z);
	CHECK(z == n);
	CHECK(memcmp(b, v, n) == 0);
	free(b);
}

void
nofile(const char *p)
{
	struct stat st;
	CHECK(lstat(p, &st) == -1 && errno == ENOENT);
}

void
mtime(const char *p, time_t t)
{
	struct timespec ts[2] = {{t, 0}, {t, 0}};
	CHECK(utimensat(AT_FDCWD, p, ts, 0) == 0);
}

int
entries(const char *p)
{
	DIR *d = opendir(p);
	struct dirent *e;
	int n = 0;
	CHECK(d != NULL);
	while ((e = readdir(d)))
		if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
			n++;
	closedir(d);
	return n;
}

unsigned char *
pattern(size_t n)
{
	unsigned char *p = xmalloc(n);
	uint32_t x = 2463534242U;
	size_t i;
	for (i = 0; i < n; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		p[i] = x;
	}
	return p;
}

double
monotime(void)
{
	struct timespec t;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
	return t.tv_sec + t.tv_nsec / 1e9;
}

void
track(pid_t p)
{
	CHECK(nchildren < 512);
	children[nchildren++] = p;
}

pid_t
child(void)
{
	pid_t p = fork();
	CHECK(p >= 0);
	if (p)
		track(p);
	else {
		nchildren = 0;
		alarm(25);
	}
	return p;
}

void
reap(pid_t p)
{
	int s;
	size_t i;
	CHECK(waitpid(p, &s, 0) == p);
	for (i = 0; i < nchildren; i++)
		if (children[i] == p)
			children[i] = 0;
	CHECK(WIFEXITED(s) && WEXITSTATUS(s) == 0);
}

int
listener(int af, unsigned short *port)
{
	struct sockaddr_storage ss;
	socklen_t len;
	int fd, one = 1;
	memset(&ss, 0, sizeof(ss));
	if (af == AF_INET) {
		struct sockaddr_in *a = (void *) &ss;
		a->sin_family = af;
		a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		len = sizeof(*a);
	} else {
		struct sockaddr_in6 *a = (void *) &ss;
		a->sin6_family = af;
		a->sin6_addr = in6addr_loopback;
		len = sizeof(*a);
	}
	fd = socket(af, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (bind(fd, (void *) &ss, len) || listen(fd, 16) || getsockname(fd,
	    (void *) &ss, &len)) {
		close(fd);
		return -1;
	}
	*port = ntohs(af == AF_INET ? ((struct sockaddr_in *) & ss)->sin_port : ((struct sockaddr_in6 *) & ss)->sin6_port);
	return fd;
}

void
record(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	CHECK(fd >= 0);
	CHECK(writeall(fd, s, strlen(s)) == 0);
	CHECK(close(fd) == 0);
}

struct result
run(const char *const * args, const char *const * env)
{
	struct result r;
	char *argv[128], *ep[128];
	char a[] = "/tmp/fetch-stdout.XXXXXXXX",
	    b[] = "/tmp/fetch-stderr.XXXXXXXX";
	int out = mkstemp(a), err = mkstemp(b), status, i, j;
	pid_t p;
	double start = monotime();
	CHECK(out >= 0 && err >= 0);
	unlink(a);
	unlink(b);
	memset(&r, 0, sizeof(r));
	argv[0] = fetchbin;
	for (i = 0; args && args[i]; i++) {
		CHECK(i < 125);
		argv[i + 1] = (char *)args[i];
	}
	argv[i + 1] = NULL;
	ep[0] = "PATH=/bin:/usr/bin:/usr/local/bin";
	ep[1] = fmt("HOME=%s", testdir);
	for (j = 0; env && env[j]; j++) {
		CHECK(j < 124);
		ep[j + 2] = (char *)env[j];
	}
	ep[j + 2] = NULL;
	p = child();
	if (p == 0) {
		struct rlimit lim = {0, 0};
		int fd;
		alarm(0);
		/* stderr first, so that a later failure is captured as well */
		if (dup2(err, 2) < 0)
			setup_failed("dup2 stderr");
		if (run_limit) {
			if (setrlimit(RLIMIT_FSIZE, &lim) < 0)
				setup_failed("setrlimit");
			signal(SIGXFSZ, SIG_IGN);
		}
		umask(run_umask);
		if ((fd = open("/dev/null", O_RDONLY)) < 0)
			setup_failed("open /dev/null");
		if (dup2(fd, 0) < 0)
			setup_failed("dup2 stdin");
		close(fd);
		if (run_sink) {
			if ((fd = open(run_sink, O_WRONLY | O_CREAT | O_TRUNC,
			    0600)) < 0)
				setup_failed("open output sink");
			if (dup2(fd, 1) < 0)
				setup_failed("dup2 stdout");
			close(fd);
		} else if (dup2(out, 1) < 0)
			setup_failed("dup2 stdout");
		closefrom(3);
		execve(fetchbin, argv, ep);
		setup_failed("execve");
	}
	for (;;) {
		pid_t q = waitpid(p, &status, WNOHANG);
		if (q == p)
			break;
		CHECK(q == 0 || (q < 0 && errno == EINTR));
		if (monotime() - start > 15)
			fail(__FILE__, __LINE__, "fetch exceeded 15s watchdog");
		usleep(10000);
	}
	for (size_t k = 0; k < nchildren; k++)
		if (children[k] == p)
			children[k] = 0;
	r.seconds = monotime() - start;
	r.sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	r.code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	struct stat st;
	CHECK(fstat(out, &st) == 0);
	CHECK(st.st_size >= 0 && st.st_size < 64 * 1024 * 1024);
	r.outlen = st.st_size;
	r.out = xmalloc(r.outlen + 1);
	CHECK(lseek(out, 0, SEEK_SET) == 0);
	CHECK(readexact(out, r.out, r.outlen) == 0);
	CHECK(fstat(err, &st) == 0);
	CHECK(st.st_size >= 0 && st.st_size < 64 * 1024 * 1024);
	r.errlen = st.st_size;
	r.err = xmalloc(r.errlen + 1);
	CHECK(lseek(err, 0, SEEK_SET) == 0);
	CHECK(readexact(err, r.err, r.errlen) == 0);
	close(out);
	close(err);
	free(ep[1]);
	if (r.code == 126)
		fail(__FILE__, __LINE__, "could not run %s: %.*s", fetchbin,
		    (int)r.errlen, r.err);
	return r;
}

/*
 * Tests that expect a lookup of a .invalid name to fail promptly cannot say
 * anything when the host's resolver is slow or unreachable.  Ask it once,
 * from a child, and give it three seconds.
 */
int
resolver_answers(void)
{
	struct addrinfo hints, *res;
	double start = monotime();
	int status, answered = 0;
	pid_t p = child();
	size_t i;

	if (p == 0) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		if (getaddrinfo("probe.invalid", NULL, &hints, &res) == 0)
			freeaddrinfo(res);
		_exit(0);
	}
	while (!answered && monotime() - start < 3) {
		pid_t q = waitpid(p, &status, WNOHANG);
		if (q == p)
			answered = 1;
		else
			CHECK(q == 0 || (q < 0 && errno == EINTR));
		if (!answered)
			usleep(10000);
	}
	if (!answered) {
		kill(p, SIGKILL);
		CHECK(waitpid(p, &status, 0) == p);
	}
	for (i = 0; i < nchildren; i++)
		if (children[i] == p)
			children[i] = 0;
	return answered;
}

void
result_free(struct result *r)
{
	free(r->out);
	free(r->err);
}

void
ok(struct result *r)
{
	if (r->sig || r->code)
		fail(__FILE__, __LINE__,
		    "expected success, code %d signal %d: %s", r->code,
		    r->sig, r->err);
}

void
bad(struct result *r)
{
	if (r->sig || r->code == 0)
		fail(__FILE__, __LINE__,
		    "expected ordinary failure, code %d signal %d: %s",
		    r->code, r->sig, r->err);
}

void
errhas(struct result *r, const char *s)
{
	if (!strstr(r->err, s))
		fail(__FILE__, __LINE__, "stderr lacks '%s': %s", s, r->err);
}

void
outeq(struct result *r, const void *p, size_t n)
{
	CHECK(r->outlen == n);
	CHECK(memcmp(r->out, p, n) == 0);
}

static int
rmnode(const char *p, const struct stat *s, int t, struct FTW *f)
{
	(void)s;
	(void)t;
	(void)f;
	return remove(p);
}

static void
intr(int s)
{
	(void)s;
	interrupted = 1;
}

int
main(int argc, char **argv)
{
	char base[] = "/tmp/fetch-regress.XXXXXXXX", cwd[4096];
	size_t i;
	int status, failed = 0, passed = 0, skipped = 0, selected = 0;
	pid_t p;
	CHECK(getcwd(suitedir, sizeof(suitedir)) != NULL);
	const char *bin = getenv("FETCH_BIN");
	if (!bin)
		bin = "../../fetch";
	CHECK(realpath(bin, fetchbin) != NULL);
	CHECK(access(fetchbin, X_OK) == 0);
	if (argc == 2 && !strcmp(argv[1], "-l")) {
		for (i = 0; i < ntests; i++)
			puts(tests[i].name);
		return 0;
	}
	CHECK(mkdtemp(base) != NULL);
	CHECK(getcwd(cwd, sizeof(cwd)) != NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, intr);
	signal(SIGTERM, intr);
	for (i = 0; i < ntests && !interrupted; i++) {
		if (argc > 1) {
			int match = 0;
			for (int j = 1; j < argc; j++)
				if (strstr(tests[i].name, argv[j]))
					match = 1;
			if (!match)
				continue;
		}
		selected++;
		snprintf(testdir, sizeof(testdir), "%s/%zu", base, i);
		CHECK(mkdir(testdir, 0700) == 0);
		fflush(NULL);
		p = fork();
		CHECK(p >= 0);
		if (!p) {
			setpgid(0, 0);
			signal(SIGINT, SIG_DFL);
			signal(SIGTERM, SIG_DFL);
			alarm(90);
			CHECK(chdir(testdir) == 0);
			tests[i].fn();
			exit(cleanup());
		}
		setpgid(p, p);
		double start = monotime();
		for (;;) {
			pid_t q = waitpid(p, &status, WNOHANG);
			if (q == p)
				break;
			CHECK(q == 0 || (q < 0 && errno == EINTR));
			if (interrupted || monotime() - start > 95) {
				kill(-p, SIGKILL);
				waitpid(p, &status, 0);
				break;
			}
			usleep(20000);
		}
		kill(-p, SIGKILL);
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			printf("PASS %s\n", tests[i].name);
			passed++;
		} else if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
			printf("SKIP %s\n", tests[i].name);
			skipped++;
		} else {
			printf("FAIL %s (status %d)\n", tests[i].name, status);
			failed++;
		}
		fflush(stdout);
	}
	CHECK(chdir(cwd) == 0);
	CHECK(nftw(base, rmnode, 32, FTW_DEPTH | FTW_PHYS) == 0);
	printf("%d passed, %d failed, %d skipped\n", passed, failed, skipped);
	return failed || interrupted || !selected ? 1 : 0;
}
