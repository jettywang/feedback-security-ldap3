#!/usr/bin/env bash
# Generate a local-only PKI for the SASL EXTERNAL demo. No external directory needed.
# Cert subject CN is deliberately NOT a directory DN, to prove the two are different namespaces.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PKI="$HERE/pki"
mkdir -p "$PKI"
cd "$PKI"

DAYS=3
# 1. Trust anchor. Server presents a cert chained to it; the client trusts it for server auth.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout ca.key -out ca.crt -days "$DAYS" \
  -subj "/O=Demo Trust Anchor/CN=Demo Issuing CA" 2>/dev/null

# 2. Server certificate. CN is a host name, never used as an authorization identity.
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/O=Demo Trust Anchor/CN=ldap.example.test" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "$DAYS" 2>/dev/null

# 3. Client certificate. Subject identifies the *TLS client* (the connector process),
#    not the directory account the server may eventually authorize.
openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
  -subj "/O=Demo Connectors/CN=svc-connector/UID=connector-7" 2>/dev/null
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days "$DAYS" 2>/dev/null

rm -f *.csr *.srl
chmod 600 *.key
echo "PKI material generated in $PKI"
openssl x509 -in client.crt -noout -subject -issuer
