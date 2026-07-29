#!/bin/sh
# Self-signed certificate for the TLS examples, into a gitignored directory.
#
#   scripts/gen-certs.sh          # writes certs/cert.pem and certs/key.pem
#
# Never commit what this produces. A private key in a repository is found later
# by whoever greps for BEGIN PRIVATE KEY, and "it was only a test key" is not a
# thing anyone checks before trying it.
#
# rustls requires the Subject Alternative Name extension and ignores commonName,
# so the SAN list is the part that matters. `host.docker.internal` is there for
# the Autobahn client, which runs in a container and reaches the host by that
# name; it validates nothing, but a cert that names the host it is reached by
# keeps the failure modes honest if validation is ever turned on.
set -eu
cd "$(dirname "$0")/.."
mkdir -p certs

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1" \
  2>/dev/null

chmod 600 certs/key.pem
echo "wrote certs/cert.pem and certs/key.pem (gitignored, self-signed, 365 days)"
openssl x509 -in certs/cert.pem -noout -subject -ext subjectAltName
