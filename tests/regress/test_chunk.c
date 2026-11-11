/* ISC: see LICENSE. Chunk status must not be confused with a narrowed size. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "server.h"
static struct result
chunk(const char *body, const char *out)
{
	char *p = fmt("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%s", body);
	struct server s = rawserver(p, strlen(p), 0);
	free(p);
	return run(ARGS("-q", "-o", out, url(&s, "/x")), NULL);
}

void
TestChunkSizeMalformed(void)
{
	const char *a[] = {";ext", " ", "xyz", "+5", "0x5", "5z",
	    "10000000000000000", "100000000000000000000", "100000000",
	    "8000000000000000", "ffffffffffffffff",
	    "ffffffffffffffffffffffffffffffffffffffff"};
	for (size_t i = 0; i < sizeof(a) / sizeof(*a); i++) {
		struct result r = chunk(fmt("5\r\nhello\r\n%s\r\nNEVER-DELIVERED\r\n0\r\n\r\n", a[i]), "out");
		bad(&r);
		nofile("out");
	}
}

void
TestChunkSizeValid(void)
{
	const char *a[] = {"5;name=value\r\nhello\r\n0\r\n\r\n",
	    "5 ;x\r\nhello\r\n0\r\n\r\n", "A\r\nhelloworld\r\n0\r\n\r\n",
	    "0000005\r\nhello\r\n0\r\n\r\n", "5\r\nhello\r\n0;done\r\n\r\n",
	    "5\r\nhello\r\n0\r\nX-Sum: 1\r\n\r\n"};
	for (int i = 0; i < 6; i++) {
		struct result r = chunk(a[i], "-");
		ok(&r);
		outeq(&r, i == 2 ? "helloworld" : "hello", i == 2 ? 10 : 5);
	}
}

void
TestChunkMissingFinalCRLF(void)
{
	const char *a[] = {"5\r\nhello\r\n0\r\n",
	    "5\r\nhello\r\n0\r\nX-Trailer: 1\r\n"};
	for (int i = 0; i < 2; i++) {
		struct result r = chunk(a[i], "out");
		bad(&r);
	}
}

/* Every byte after chunk data must be exactly CRLF. */
void
TestChunkBadTerminator(void)
{
	const char *a[] = {"XX", "\r", "\n", "\n\r", "\r\r", " \r\n", ""};
	for (size_t i = 0; i < sizeof(a) / sizeof(*a); i++) {
		struct result r = chunk(fmt("5\r\nhello%s3\r\nabc\r\n0\r\n\r\n",
		    a[i]), "out");
		bad(&r);
		nofile("out");
	}
}

/* The connection closing anywhere inside the framing is an error. */
void
TestChunkTruncatedAtBoundaries(void)
{
	const char *a[] = {"5\r\nhel", "5\r\nhello", "5\r\nhello\r",
	    "5\r\nhello\r\n", "5\r\nhello\r\n1", "5\r\nhello\r\n3\r\nab",
	    "5\r\nhello\r\n0\r\n"};
	for (size_t i = 0; i < sizeof(a) / sizeof(*a); i++) {
		struct result r = chunk(a[i], "out");
		bad(&r);
		nofile("out");
	}
}

/*
 * Transfer-Encoding overrides Content-Length (RFC 9112 6.3): a chunked body
 * ends at its last chunk, whatever length is also announced and in
 * whichever order the headers come, and its size is not known up front.
 */
void
TestChunkedOverridesContentLength(void)
{
	static const char *const hdr[] = {
		"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n",
		"Content-Length: 3\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: chunked\r\nContent-Length: 100\r\n",
		"Content-Length: 100\r\nTransfer-Encoding: chunked\r\n",
		"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n",
	};
	static const char body[] = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
	for (size_t i = 0; i < sizeof(hdr) / sizeof(*hdr); i++) {
		char *p = fmt("HTTP/1.1 200 OK\r\n%s\r\n%s", hdr[i], body);
		struct server s = rawserver(p, strlen(p), 0);
		struct result r = run(ARGS("-q", "-o", "-", url(&s, "/x")), NULL);

		ok(&r);
		outeq(&r, "hello world", 11);
		result_free(&r);
		r = run(ARGS("-q", "-s", url(&s, "/x")), NULL);
		ok(&r);
		outeq(&r, "Unknown\n", 8);
		result_free(&r);
		free(p);
	}
}

/*
 * A body must arrive byte for byte whatever the framing and however fetch
 * is asked to read it: chunk sizes straddle the 4, 16 and 64 KiB read sizes.
 */
#define BODYLEN 300000

static size_t
chunkwire(unsigned char *w, const unsigned char *p, const char *ext)
{
	static const size_t sz[] = {1, 5, 4095, 4096, 4097, 16383, 16384,
	    16385, 65535, 65536, 65537, 100};
	size_t off = 0, len = 0;
	for (size_t i = 0; off < BODYLEN; i++) {
		size_t n = sz[i % (sizeof(sz) / sizeof(*sz))];
		if (n > BODYLEN - off)
			n = BODYLEN - off;
		len += snprintf((char *)w + len, 32, "%zx%s\r\n", n, ext);
		memcpy(w + len, p + off, n);
		len += n;
		memcpy(w + len, "\r\n", 2);
		len += 2;
		off += n;
	}
	memcpy(w + len, "0\r\n\r\n", 5);
	return len + 5;
}

void
TestBodyIntegrity(void)
{
	const char *mode[] = {"", ";x=y", NULL};	/* chunk extension; NULL: length */
	const char *bsize[] = {NULL, "16384", "65536", "1048576"};
	unsigned char *body = pattern(BODYLEN);
	unsigned char *wire = xmalloc(2 * BODYLEN);
	for (int m = 0; m < 3; m++) {
		size_t hl, n;
		char *hdr = m < 2 ? fmt("HTTP/1.1 200 OK\r\nTransfer-Encoding: "
		    "chunked\r\nConnection: close\r\n\r\n") :
		    fmt("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n"
		    "Connection: close\r\n\r\n", BODYLEN);
		hl = strlen(hdr);
		memcpy(wire, hdr, hl);
		free(hdr);
		if (m < 2)
			n = hl + chunkwire(wire + hl, body, mode[m]);
		else {
			memcpy(wire + hl, body, BODYLEN);
			n = hl + BODYLEN;
		}
		struct server s = rawserver(wire, n, 0);
		for (int b = 0; b < 4; b++) {
			const char *args[8];
			int k = 0;
			args[k++] = "-q";
			if (bsize[b]) {
				args[k++] = "-B";
				args[k++] = bsize[b];
			}
			args[k++] = "-o";
			args[k++] = "out";
			args[k++] = url(&s, "/x");
			args[k] = NULL;
			struct result r = run(args, NULL);
			ok(&r);
			fileeq("out", body, BODYLEN);
		}
	}
}
