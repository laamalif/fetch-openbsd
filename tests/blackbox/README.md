# fetch black-box test suite

Go tests that run the real `fetch` binary against local HTTP, HTTPS, FTP,
SOCKS5 and raw-TCP fault servers.  No network access or extra dependencies
(Go stdlib only).  Every server listens on 127.0.0.1.

    pkg_add go
    make                                # in the top-level directory
    cd tests/blackbox
    go test ./...                       # uses ../../fetch
    FETCH_BIN=/path/to/fetch go test -v ./...
    go test -run TLS -v ./...

| File              | Covers |
|-------------------|--------|
| `http_test.go`    | GET, `-o`, sizes, mtime/`-n`, 4xx/5xx, redirects/`-A`, chunked, headers, auth, `-s`, `-S`, `-i`, `-r`, `-m`, `-T` |
| `fault_test.go`   | truncated, stalled and garbage responses, refused, DNS, IPv4/IPv6 |
| `tls_test.go`     | untrusted cert, `--ca-cert`, `--no-verify-peer`, hostname check |
| `ftp_test.go`     | passive, active, login, missing file, REST resume (built-in fake server) |
| `socks_test.go`   | `SOCKS5_PROXY` against a fake RFC 1928 server: name and port sent, error replies, wrong version |
| `sandbox_test.go` | `file:` redirect not followed, `-o -` writes nothing, `-o` elsewhere, `-i` file |
| `misc_test.go`    | `HTTP_PROXY`/`NO_PROXY`, `file://`, `-l`, write errors, bad CLI args |

fetch runs with a clean environment (`PATH`, `HOME`=temp dir), so proxy and
SSL variables from your shell do not affect the results.
