/* ISC: test-only helpers for the OpenBSD fetch regression suite. */
#ifndef HARNESS_H
#define HARNESS_H
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define MODTIME 1577934245
#define HELLO "hello, world\n"
#define CHECK(x) do { if (!(x)) fail(__FILE__, __LINE__, "%s", #x); } while (0)
#define ARGS(...) (const char *const[]){__VA_ARGS__, NULL}
struct result {
	int code, sig;
	double seconds;
	char *out, *err;
	size_t outlen, errlen;
};
struct test {
	const char *name;
	void (*fn)(void);
};
extern char testdir[4096], fetchbin[4096], suitedir[4096];
extern mode_t run_umask;
extern int run_limit;
extern const char *run_sink;
void fail(const char *, int, const char *, ...) __attribute__((format(printf,3,4),noreturn));
void skip(const char *);
void *xmalloc(size_t);
char *fmt(const char *, ...) __attribute__((format(printf,1,2)));
void putfile(const char *, const void *, size_t, mode_t);
char *getfile(const char *, size_t *);
void fileeq(const char *, const void *, size_t);
void nofile(const char *);
void mtime(const char *, time_t);
int entries(const char *);
unsigned char *pattern(size_t);
struct result run(const char *const *, const char *const *);
void result_free(struct result *);
void ok(struct result *);
void bad(struct result *);
void errhas(struct result *, const char *);
void outeq(struct result *, const void *, size_t);
pid_t child(void);
void reap(pid_t);
void track(pid_t);
double monotime(void);
int resolver_answers(void);
int listener(int, unsigned short *);
int readexact(int, void *, size_t);
int writeall(int, const void *, size_t);
void line(int, char *, size_t);
void record(const char *, const char *);
struct ftp {
	unsigned short port;
	pid_t pid;
};
struct ftp newftp(const char *, const unsigned char *, size_t, int);
extern const char *ftp_size_reply;
extern const struct test tests[];
extern const size_t ntests;
#endif
