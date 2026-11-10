#!/bin/sh
# pledge(2)/unveil(2) tests.  Needs go-httpbin and process accounting
# (accton(8)), so that lastcomm(1) can report a pledge or unveil violation.
# Usage: sh tests/sandbox.sh   (from the source directory, after "make")

F=${FETCH:-./fetch}
case $F in /*) ;; *) F=$(pwd)/$F;; esac
PORT=${PORT:-18080}
H=http://127.0.0.1:$PORT
T=$(mktemp -d /tmp/sandbox.XXXXXXXXXX) || exit 1
fail=0

go-httpbin -host 127.0.0.1 -port $PORT -max-duration 30s \
    >/dev/null 2>&1 </dev/null &
srv=$!
trap 'kill $srv 2>/dev/null; rm -rf "$T"' 0 1 2 15
n=0
while [ $n -lt 20 ] && ! nc -z 127.0.0.1 $PORT 2>/dev/null; do
	sleep 0.5; n=$((n + 1))
done
nc -z 127.0.0.1 $PORT 2>/dev/null || { echo "go-httpbin did not start"; exit 1; }

# run <description> <expected exit status> <command ...>
run()
{
	desc=$1; want=$2; shift 2
	timeout 30 "$@" >"$T/out" 2>"$T/err"
	rc=$?
	flags=$(lastcomm fetch | head -1 | awk '{print $2}')
	case $flags in
	*[PU]*)	echo "FAIL: $desc (killed or denied: flags $flags)"; fail=1;;
	*)	if [ $rc -eq "$want" ]; then
			echo "ok:   $desc"
		else
			echo "FAIL: $desc (exit $rc, wanted $want)"; fail=1
		fi;;
	esac
}

same()
{
	if cmp -s "$1" "$2"; then
		echo "ok:   $3"
	else
		echo "FAIL: $3"; fail=1
	fi
}

cd "$T" || exit 1
mkdir src dst
echo hello > src/a.txt
dd if=/dev/urandom of=src/big bs=1024 count=300 2>/dev/null
printf 'machine 127.0.0.1 login alice password s3cret\n' > netrc
chmod 600 netrc

run "http to stdout"		0 $F -q -o - $H/get
run "http to file"		0 $F -q -o dst/get.json $H/get
run "http, name from URL, cwd"	0 $F -q $H/bytes/100
run "http to directory"		0 $F -q -o dst $H/bytes/100
run "http redirect chain"	0 $F -q -o - $H/redirect/3
run "http error status"		1 $F -q -o - $H/status/404
run "http timeout"		1 $F -q -T 2 -o - $H/delay/5
run "http -m sets mtime"	0 $F -q -m -o dst/lm "$H/response-headers?Last-Modified=Wed,%2021%20Oct%202015%2007:28:00%20GMT"
[ "$(stat -f %m dst/lm)" = 1445412480 ] && echo "ok:   -m mtime" ||
    { echo "FAIL: -m mtime"; fail=1; }
run "http -r resume"		0 sh -c "dd if=/dev/zero of=dst/part bs=100 count=1 2>/dev/null; $F -q -r -o dst/part $H/range/1000"
[ "$(stat -f %z dst/part)" = 1000 ] && echo "ok:   -r size" ||
    { echo "FAIL: -r size"; fail=1; }
run "http -i reference file"	0 $F -q -i src/a.txt -o dst/ims $H/bytes/10
run "http .netrc (-N)"		0 $F -q -N "$T/netrc" -o - $H/basic-auth/alice/s3cret
run "http without credentials"	1 $F -q -o - $H/basic-auth/alice/s3cret
run "http credentials in URL"	0 $F -q -o - http://alice:s3cret@127.0.0.1:$PORT/basic-auth/alice/s3cret
run "HOME and NETRC unset"	0 env -u HOME -u NETRC $F -q -o - $H/get
run "NETRC empty"		0 env NETRC= $F -q -o - $H/get
run "SSL_CA_CERT_PATH empty"	0 env SSL_CA_CERT_PATH= $F -q -o - $H/get
run "http via HTTP proxy"	0 env HTTP_PROXY=http://127.0.0.1:$PORT $F -q -o - http://127.0.0.1:$PORT/get
run "file to stdout"		0 $F -q -o - file://$T/src/a.txt
run "file to file"		0 $F -q -o dst/b.txt file://$T/src/a.txt
same src/a.txt dst/b.txt "file copy content"
run "file overwrite, keeps mode" 0 sh -c "echo old > dst/o; chmod 600 dst/o; $F -q -o dst/o file://$T/src/a.txt"
same src/a.txt dst/o "file overwrite content"
[ "$(stat -f %Lp dst/o)" = 600 ] && cmp -s src/a.txt dst/o &&
    echo "ok:   overwrite keeps mode" ||
    { echo "FAIL: overwrite keeps mode"; fail=1; }
run "file -l symlink"		0 $F -q -l -o dst/ln file://$T/src/a.txt
run "file -s size"		0 $F -q -s file://$T/src/big
run "file missing"		1 $F -q -o - file://$T/src/nope
run "output in missing dir"	1 $F -q -o dst/no/such/x file://$T/src/a.txt
run "https via system CA"	0 $F -q -o - https://www.openbsd.org/robots.txt
run "https bad certificate"	1 $F -q -o - https://expired.badssl.com/
# --ca-path wants a directory of certificates named by hash.
mkdir ca
awk '/BEGIN CERTIFICATE/ { n++ } { print > sprintf("ca/c%03d.pem", n) }' \
    /etc/ssl/cert.pem
for c in ca/c*.pem; do
	h=$(openssl x509 -hash -noout -in "$c" 2>/dev/null) &&
	    [ -n "$h" ] && ln -sf "${c#ca/}" "ca/$h.0"
done
run "https --ca-path"		0 $F -q --ca-path="$T/ca" -o - https://www.openbsd.org/robots.txt
run "https --ca-path, empty dir" 1 sh -c "mkdir -p empty; $F -q --ca-path=$T/empty -o - https://www.openbsd.org/robots.txt"
run "https --ca-cert"		0 $F -q --ca-cert=/etc/ssl/cert.pem -o - https://www.openbsd.org/robots.txt
run "https via HTTP proxy"	0 env HTTP_PROXY=http://192.168.1.254:8121 $F -q -o - https://www.openbsd.org/robots.txt
run "ftp passive"		0 $F -q -o - ftp://ftp.gnu.org/README
run "ftp active"		0 $F -q -p -o - ftp://ftp.gnu.org/README

# What the sandbox must refuse.
run "redirect to file: is not followed" 1 $F -q -o - "$H/redirect-to?url=file:///etc/passwd"
grep -q '^root:' "$T/out" && { echo "FAIL: /etc/passwd leaked"; fail=1; } ||
    echo "ok:   /etc/passwd not leaked"

# Progress meter and setproctitle need a terminal.
script -c "$F -o dst/pty.bin $H/bytes/20000" "$T/pty" >/dev/null 2>&1
flags=$(lastcomm fetch | head -1 | awk '{print $2}')
case $flags in *[PU]*) echo "FAIL: progress meter (flags $flags)"; fail=1;;
*) [ "$(stat -f %z dst/pty.bin)" = 20000 ] && echo "ok:   progress meter on a tty" ||
    { echo "FAIL: progress meter output"; fail=1; };; esac

exit $fail
