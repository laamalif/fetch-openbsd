# fetch black-box test suite

This suite is written in C and lives in `tests/regress`; this directory holds
only this note.

The tests run the real `fetch` binary against local HTTP, HTTPS, FTP, SOCKS5
and raw-TCP fault servers.  No network access and nothing outside the base
system (cc, libtls, openssl).  Every server listens on 127.0.0.1.

    make                                # in the top-level directory
    make regress
    cd tests/regress
    ./fetch-regress -l                  # list the cases
    ./fetch-regress Chunk SOCKS5        # run cases whose names contain these
    FETCH_BIN=/path/to/fetch ./fetch-regress Retry

`tests/regress/USAGE` has the details.

| File              | Covers |
|-------------------|--------|
| `test_http.c`     | GET, `-o`, sizes, mtime/`-n`, 4xx/5xx, redirects/`-A`, headers, auth, `-s`, `-S`, `-i`, `-m`, `-T` |
| `test_chunk.c`    | chunk sizes, extensions, terminators, truncation; body integrity under `-B` |
| `test_range.c`    | `-r`, resume position and identity, symlinks |
| `test_retry.c`    | `-a`: retry requests agree with the bytes on disk |
| `test_output.c`   | atomic replacement, permissions, special bits, dangling symlinks |
| `test_fault.c`    | truncated, stalled and garbage responses, refused, DNS, IPv4/IPv6 |
| `test_diag.c`     | diagnostics do not alter bodies or expose passwords |
| `test_verbose.c`  | `-v` never shows credentials |
| `test_regress.c`  | credentials stay in their origin; final write errors |
| `test_tls.c`      | untrusted cert, `--ca-cert`, `--no-verify-peer`, hostname check |
| `test_ftp.c`      | passive, active, login, missing file, REST resume (built-in fake server) |
| `test_socks.c`    | `SOCKS5_PROXY` against a fake RFC 1928 server: name and port sent, error replies, wrong version, fragmented replies |
| `test_sandbox.c`  | `file:` redirect not followed, `-o -` writes nothing, `-o` elsewhere, `-i` file |
| `test_misc.c`     | `HTTP_PROXY`/`NO_PROXY`, `file://`, write errors, bad CLI args |

`coverage.tsv` lists each case with the assertions and parameter sets it covers.

fetch runs with a clean environment (`PATH`, `HOME`=temp dir), so proxy and
SSL variables from your shell do not affect the results.  A case skips, with
the reason, when the system cannot provide what it needs: a second loopback
address, root privileges, IPv6, or a resolver that answers.
