/*
 * Copyright (c) 2026 laamalif <laamalif@pm.me>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fetch.h>

#include "sandbox.h"

static void	 sandbox_unveil(const char *, const char *);
static void	 sandbox_unveil_dirname(const char *, const char *);

/*
 * An empty path, such as NETRC= in the environment, names nothing.  A path
 * that does not exist cannot be reached anyway: leave it hidden and let the
 * later open(2) report ENOENT as it always did.
 */
static void
sandbox_unveil(const char *path, const char *perms)
{
	if (*path == '\0')
		return;
	if (unveil(path, perms) == -1 && errno != ENOENT)
		err(1, "unveil %s", path);
}

static void
sandbox_unveil_dirname(const char *path, const char *perms)
{
	char copy[PATH_MAX];

	if (strlcpy(copy, path, sizeof(copy)) >= sizeof(copy))
		errx(1, "%s: path too long", path);
	sandbox_unveil(dirname(copy), perms);
}

/*
 * Restrict the process to what the transfers about to be made can need.
 * Everything that depends on the environment, the password database or
 * the system CA bundle has been resolved by now.
 *
 * urls, nurls	the URLs to fetch; file: sources are unveiled read-only
 * outpath	where output goes, or NULL for standard output
 * outisdir	outpath is a directory, otherwise a file in its directory
 * infile	the -i reference file, or NULL
 *
 * Directories are unveiled rather than files wherever the program may
 * replace a file, since a more specific unveil would override the
 * directory: with -i the reference file is often the output file too.
 */
void
sandbox(char *const *urls, int nurls, const char *outpath, int outisdir,
    const char *infile)
{
	const char *promises, *netrc, *capath;
	struct url *u;
	int i;

	/* may read the password database, so it must precede unveil */
	netrc = fetch_netrc_path();

	/* nothing is visible unless it is unveiled below */
	if (unveil("/", "") == -1)
		err(1, "unveil /");

	if (netrc != NULL)
		sandbox_unveil(netrc, "r");
	if ((capath = getenv("SSL_CA_CERT_PATH")) != NULL)
		sandbox_unveil(capath, "r");
	if (infile != NULL)
		sandbox_unveil_dirname(infile, "r");
	for (i = 0; i < nurls; i++) {
		if ((u = fetchParseURL(urls[i])) == NULL)
			continue;
		if (strcmp(u->scheme, "file") == 0 ||
		    (*u->scheme == '\0' && *u->host == '\0'))
			sandbox_unveil(u->doc, "r");
		fetchFreeURL(u);
	}
	if (outpath != NULL) {
		if (outisdir)
			sandbox_unveil(outpath, "rwc");
		else
			sandbox_unveil_dirname(outpath, "rwc");
	}
	if (unveil(NULL, NULL) == -1)
		err(1, "unveil");

	/*
	 * tty: the progress meter and password prompt use terminal ioctls.
	 * rpath: .netrc, -i and file: sources, limited by unveil.
	 * wpath cpath fattr chown: the output file, its temporary file,
	 * its times and modes, and its owner when replacing a file.
	 */
	if (outpath != NULL)
		promises = "stdio rpath wpath cpath fattr chown dns inet tty";
	else
		promises = "stdio rpath dns inet tty";
	if (pledge(promises, NULL) == -1)
		err(1, "pledge");
}
