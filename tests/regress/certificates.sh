#!/bin/sh
# Test-only certificates, regenerated at execution time; base openssl only.
set -eu
umask 077
mkdir -p certs
cat > certs/config <<'CONF'
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = fetch regression
[ext]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign
subjectAltName = IP:127.0.0.1,DNS:example.com
CONF
for name in server other; do
    openssl req -new -x509 -newkey rsa:2048 -nodes -days 2 \
        -config certs/config -keyout certs/$name.key \
        -out certs/$name.pem >/dev/null 2>&1
done
