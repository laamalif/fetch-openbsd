/* ISC: FTP SIZE reply parsing, driven through fetch -s and a fake server. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "harness.h"

/*
 * Ask a fake server whose SIZE reply is "213 <reply>" for the size of a
 * file and return fetch's result.  The file itself is 100 bytes.
 */
static struct result
sizeof_reply(const char *reply, const char *flag)
{
	static const unsigned char data[100];
	struct ftp f;
	struct result r;
	char *url;

	ftp_size_reply = reply;
	f = newftp("/f", data, sizeof(data), 1);
	url = fmt("ftp://127.0.0.1:%u/f", f.port);
	if (strcmp(flag, "-s") == 0)
		r = run(ARGS("-q", "-s", url), NULL);
	else
		r = run(ARGS("-q", "-o", "out", url), NULL);
	reap(f.pid);
	free(url);
	return r;
}

static void
accepts(const char *reply, const char *printed)
{
	struct result r = sizeof_reply(reply, "-s");

	ok(&r);
	if (r.outlen != strlen(printed) + 1 ||
	    memcmp(r.out, printed, strlen(printed)) != 0 ||
	    r.out[r.outlen - 1] != '\n')
		fail(__FILE__, __LINE__, "SIZE '%s': printed '%.*s', want '%s'",
		    reply, (int)r.outlen, r.out, printed);
	result_free(&r);
}

/*
 * A SIZE reply that is not a usable size is never believed: ftp_stat() fails
 * with a protocol error, which ftp_request() treats as "size unknown" and
 * carries on.  The reply must therefore read as Unknown, not as a wrapped or
 * negative number.
 */
static void
rejects(const char *reply)
{
	accepts(reply, "Unknown");
}

/* Every size from 1 byte up to the largest an off_t holds is passed through. */
void
TestFTPSizeValid(void)
{
	static const char *const v[] = {
		"1",
		"100",
		"2147483647",			/* 2^31 - 1 */
		"2147483648",			/* 2^31 */
		"4294967296",			/* 2^32 */
		"4398046511104",		/* 4 TiB */
		"9223372036854775807",		/* LLONG_MAX, the largest off_t */
		"0000000000000000000000100",	/* leading zeros are not digits */
		"  100",			/* leading blanks */
		"100 bytes",			/* trailing words */
	};
	static const char *const want[] = {
		"1", "100", "2147483647", "2147483648", "4294967296",
		"4398046511104", "9223372036854775807", "100", "100", "100",
	};
	size_t i;

	for (i = 0; i < sizeof(v) / sizeof(v[0]); i++)
		accepts(v[i], want[i]);
}

/* A size of 0 has always meant "not known"; so does a reply with none. */
void
TestFTPSizeUnknown(void)
{
	accepts("0", "Unknown");
	accepts("000", "Unknown");
	accepts("", "Unknown");
}

/* One past the largest off_t, and anything beyond, is not a size. */
void
TestFTPSizeOverflow(void)
{
	static const char *const v[] = {
		"9223372036854775808",		/* LLONG_MAX + 1 */
		"9223372036854775809",
		"9223372036854775810",
		"10000000000000000000",
		"18446744073709551615",		/* 2^64 - 1 */
		"18446744073709551616",		/* 2^64: wraps to 0 */
		"18446744073709551617",		/* 2^64 + 1: wraps to 1 */
		"18446744073709551716",		/* 2^64 + 100: wraps to 100 */
		"99999999999999999999",
		"123456789012345678901234567890123456789012345678901234567890",
	};
	size_t i;

	for (i = 0; i < sizeof(v) / sizeof(v[0]); i++)
		rejects(v[i]);
}

/* Text that is not a size is not a size, whatever digits it starts with. */
void
TestFTPSizeMalformed(void)
{
	rejects("12abc");
	rejects("1x");
	rejects("abc");
	rejects("-1");
	rejects("+1");
	rejects("1,5");
	rejects("0x10");
}

/*
 * The same guard on a real download.  A size that wraps to 100 or to 1 must
 * neither satisfy nor trip the length checks: the download just runs to the
 * end of the data and succeeds, exactly as if no size had been sent.
 */
void
TestFTPSizeOverflowDownload(void)
{
	static const unsigned char data[100];
	struct result r = sizeof_reply("18446744073709551617", "get");

	ok(&r);
	fileeq("out", data, sizeof(data));
	result_free(&r);
}
