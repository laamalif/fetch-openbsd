#!/bin/sh
# TLS verification tests.  Needs network access.  Usage: sh tests/tls.sh
# Run from the source directory after "make".

F=${FETCH:-./fetch}
fail=0

ok()
{
	desc=$1; shift
	if "$@" >/dev/null 2>&1; then
		echo "ok:   $desc"
	else
		echo "FAIL: $desc (expected success)"; fail=1
	fi
}

bad()
{
	desc=$1; shift
	if "$@" >/dev/null 2>&1; then
		echo "FAIL: $desc (expected failure)"; fail=1
	else
		echo "ok:   $desc"
	fi
}

ok  "valid certificate"		$F -o /dev/null https://www.openbsd.org/
bad "expired certificate"	$F -o /dev/null https://expired.badssl.com/
bad "self-signed certificate"	$F -o /dev/null https://self-signed.badssl.com/
bad "untrusted root"		$F -o /dev/null https://untrusted-root.badssl.com/
bad "host name mismatch"	$F -o /dev/null https://wrong.host.badssl.com/
bad "TLS 1.0 only server"	$F -o /dev/null https://tls-v1-0.badssl.com:1010/

ok  "--no-verify-peer, self-signed" \
    $F --no-verify-peer -o /dev/null https://self-signed.badssl.com/
ok  "SSL_NO_VERIFY_PEER, self-signed" \
    env SSL_NO_VERIFY_PEER=1 $F -o /dev/null https://self-signed.badssl.com/
ok  "--no-verify-hostname, wrong host" \
    $F --no-verify-hostname -o /dev/null https://wrong.host.badssl.com/
bad "--no-verify-hostname does not hide expiry" \
    $F --no-verify-hostname -o /dev/null https://expired.badssl.com/

ok  "--ca-cert with the system bundle" \
    $F --ca-cert=/etc/ssl/cert.pem -o /dev/null https://www.openbsd.org/
bad "--ca-cert with a missing file" \
    $F --ca-cert=/nonexistent -o /dev/null https://www.openbsd.org/
ok  "SSL_NO_TLS1_3 still connects (TLS 1.2)" \
    env SSL_NO_TLS1_3=1 $F -o /dev/null https://www.openbsd.org/
bad "SSL_NO_TLS1_2 and SSL_NO_TLS1_3 leave no protocol" \
    env SSL_NO_TLS1_2=1 SSL_NO_TLS1_3=1 $F -o /dev/null https://www.openbsd.org/

exit $fail
