#ifndef SERVER_H
#define SERVER_H
#include "harness.h"
struct server { pid_t pid; unsigned short port; char *url, *log; };
struct server httpserver(int, int);
struct server rawserver(const void *, size_t, int);
struct server redirectserver(const char *, int);
char *url(struct server *, const char *);
char *requests(struct server *);
int request_count(struct server *);
void TestTLSUntrustedRejected(void);
#endif
