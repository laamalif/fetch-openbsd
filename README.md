# fetch

An OpenBSD port of FreeBSD's [fetch(1)][1].  It retrieves files by HTTP,
HTTPS, FTP or `file:` URL, with proxy support (HTTP, FTP and SOCKS5),
resume, `.netrc` and HTTP authentication.  The transport is libtls instead
of OpenSSL, and after startup the program runs under `pledge(2)` and
`unveil(2)`.  It builds and runs on OpenBSD 8.0 (tested on arm64) and
OpenBSD 7.9 (tested on amd64).

The code is FreeBSD `stable/15` `lib/libfetch` and `usr.bin/fetch`, changed
where OpenBSD needs it and hardened where the transfer code trusted the
server too much.  See `UPSTREAM` for the exact commit.

[1]: https://man.freebsd.org/cgi/man.cgi?fetch(1)

## Build

    make
    doas make install            # stripped fetch to /usr/local/bin,
                                 # fetch.1 to /usr/local/man/man1

A static binary:

    make LDSTATIC=-static

There is no library, no `fetch(3)`, and no dependency beyond the base system.

## Differences from FreeBSD fetch

* HTTPS uses libtls.  The chain and the host name are always verified unless
  you say otherwise.  The CA bundle is `/etc/ssl/cert.pem`.
* No client certificate, key or CRL options (`--cert`, `--key`, `--crl`), and
  no `--no-sslv3`/`--no-tlsv1`.  libtls speaks TLS 1.2 and 1.3.
* Sandboxed: see SECURITY CONSIDERATIONS in fetch(1).  A server cannot make
  fetch read your files by redirecting to a `file:` URL.
* A download is written to a temporary file next to the output and renamed
  into place when it is complete, so an interrupted transfer never replaces
  a good file and a symbolic link of that name is replaced, not followed.
  `-r` is the exception: it appends to the existing file, following a
  symbolic link, as ftp(1) `-C` does.
* `-a` retries a failed transfer by resuming it where it stopped.  If the
  server starts over instead, the output is truncated and written again
  (regular files only).

### Hardening beyond FreeBSD

* Text that comes from the server or from a URL is escaped before it is
  printed, so it cannot carry terminal control sequences.
* Passwords, `Authorization` and `Proxy-Authorization` are not shown by
  `-v`, however many times it is given.
* `Content-Length`, `Content-Range` and chunk sizes are parsed strictly and
  cannot wrap; a response that contradicts itself is an error, not a guess.
* FTP data connections go to the server the control connection went to (the
  address in a `PASV` reply is ignored) and an active-mode connection is
  accepted only from that server.
* `-T` covers every wait: connecting, FTP data setup and SOCKS5 replies.
* `NO_PROXY` entries match whole host name labels:  `example.com` does not
  match `notexample.com`.

Environment: `HTTP_PROXY`, `HTTP_PROXY_AUTH`, `FTP_PROXY`, `NO_PROXY`,
`SOCKS5_PROXY`, `SSL_CA_CERT_FILE`, `SSL_CA_CERT_PATH`, `SSL_NO_VERIFY_PEER`,
`SSL_NO_VERIFY_HOSTNAME`, `SSL_NO_TLS1_2`, `SSL_NO_TLS1_3`, `NETRC` and the
other variables listed under ENVIRONMENT in fetch(1).

## Tests

    cd tests/blackbox && go test ./...
    sh tests/tls.sh
    sh tests/sandbox.sh

`tests/blackbox` is a Go suite that runs the built binary against local HTTP,
HTTPS, FTP, SOCKS5 and fault-injecting servers.  It needs no network; see its
README.  Some tests are skipped where the system cannot provide what they
need (for example a second loopback address).

`tests/tls.sh` and `tests/sandbox.sh` run against real hosts, so they need
the Internet, and `go-httpbin` in `PATH`.  `sandbox.sh` also needs process
accounting (see its header) and runs the SOCKS5 cases only if
`TEST_SOCKS5_PROXY=host:port` is set.

## Staying in sync with FreeBSD

`UPSTREAM` records the freebsd-src commit this was taken from.  To sync, diff
`lib/libfetch` and `usr.bin/fetch` between that commit and the new one, apply
the diff here, and update `UPSTREAM`.  `UPSTREAM` also lists the library
functions that were removed because nothing here calls them (upload, list and
the URL convenience wrappers): skip upstream hunks that touch those, and
check any new caller of one before bringing it back.  `libfetch/common.c`
differs most from upstream (libtls, deadlines, SOCKS5, redaction), so expect
to merge it by hand.  `docs/plans/` has the design notes
written when the port was made.  They describe the port as it started and
are not kept up to date.

## Licence

BSD-3-Clause for the FreeBSD code (`libfetch/*` and `main.c`; `libfetch/ftp.c`
also carries a Beerware notice), ISC for the new files (`sandbox.c`,
`sandbox.h`, `compat.h`).  The file headers are authoritative.
