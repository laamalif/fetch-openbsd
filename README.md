# fetch

An OpenBSD port of FreeBSD's [fetch(1)][1].  It retrieves a file by HTTP,
HTTPS, FTP or `file:` URL, with proxy support, resume, and `.netrc`.

The transport is libtls instead of OpenSSL, and after startup the program
runs under `pledge(2)` and `unveil(2)`.  It builds and runs on OpenBSD 8.0
(tested on arm64).

[1]: https://man.freebsd.org/cgi/man.cgi?fetch(1)

## Build

    make
    doas make install            # stripped fetch to /usr/local/bin,
                                 # fetch.1 to /usr/local/man/man1

A static binary:

    make LDSTATIC=-static

There is no library, no `fetch(3)`, and no extra dependency beyond the base
system.

## Differences from FreeBSD fetch

* HTTPS uses libtls.  The chain and the host name are always verified unless
  you say otherwise.  The CA bundle is `/etc/ssl/cert.pem`.
* No client certificate, key or CRL options (`--cert`, `--key`, `--crl`), and
  no `--no-sslv3`/`--no-tlsv1`.  libtls speaks TLS 1.2 and 1.3.
* Sandboxed: see SECURITY CONSIDERATIONS in fetch(1).  A server cannot make
  fetch read your files by redirecting to a `file:` URL.

Environment: `HTTP_PROXY`, `HTTP_PROXY_AUTH`, `FTP_PROXY`, `NO_PROXY`,
`SOCKS5_PROXY`, `SSL_CA_CERT_FILE`, `SSL_CA_CERT_PATH`, `SSL_NO_VERIFY_PEER`,
`SSL_NO_VERIFY_HOSTNAME`, `SSL_NO_TLS1_2`, `SSL_NO_TLS1_3`, `NETRC`.  See
fetch(1).

## Tests

    sh tests/tls.sh
    sh tests/sandbox.sh
    cd tests/blackbox && go test ./...

`tests/blackbox` is a Go suite that needs no network; see its README.  The two
shell scripts need `go-httpbin` and the Internet for the FTP cases.

## Staying in sync with FreeBSD

`UPSTREAM` records the freebsd-src commit this was taken from.  To sync, diff
`lib/libfetch` and `usr.bin/fetch` between that commit and the new one, apply
the diff here, and update `UPSTREAM`.  `docs/plans/` explains which files
changed in the port and why.

## Licence

BSD-2-Clause for the FreeBSD code (see the file headers); ISC for the new
files (`sandbox.c`, `compat.h`, ...).
