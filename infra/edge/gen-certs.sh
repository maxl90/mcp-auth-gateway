#!/usr/bin/env bash
# Generate the test PKI for the on-prem edge pattern (ADR 008), Phase 1.
#
# Produces two independent CAs and the leaf certs the mTLS chain needs:
#   public-ca   → the "server" CA a client pins; signs the edge proxy's
#                 public-facing TLS leaf (stands in for Let's Encrypt/DigiCert
#                 in a real deploy — the public leaf is NOT client-pinned in
#                 prod; you pin the CA).
#   client-ca   → issues per-customer/per-agent client certs for edge mTLS.
#   internal-ca → the proxy↔gateway inner hop: signs the gateway's TLS leaf
#                 and the proxy's client cert. The gateway trusts ONLY this CA,
#                 so nothing else on the segment can open a connection.
#
# These are throwaway test certs. Real deployments issue client certs from a
# private CA (step-ca/SCEP), short-lived, per §7 of the spec. Requires openssl.
#
# Usage:  ./gen-certs.sh [OUT_DIR]   (default: ./certs, next to this script)
set -euo pipefail

# Git Bash / MSYS on Windows rewrites a leading-slash arg like "/CN=x" into a
# Windows path. Disable that so openssl -subj is passed through verbatim.
# Harmless no-ops on Linux/macOS.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

OUT="${1:-"$(cd "$(dirname "$0")" && pwd)/certs"}"
DAYS=90
mkdir -p "$OUT"
cd "$OUT"

# $1=name  $2=CN
# CA certs need basicConstraints=CA:TRUE + keyUsage=keyCertSign — OpenSSL 3.x
# rejects a "CA" without them ("CA cert does not include key usage extension").
make_ca() {
  openssl genrsa -out "$1-ca-key.pem" 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "$1-ca-key.pem" -sha256 -days 3650 \
    -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$1-ca.pem" >/dev/null 2>&1
}

# $1=name  $2=CN  $3=ca-prefix  $4=extfile
make_leaf() {
  openssl genrsa -out "$1-key.pem" 2048 >/dev/null 2>&1
  openssl req -new -key "$1-key.pem" -subj "/CN=$2" -out "$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$1.csr" -CA "$3-ca.pem" -CAkey "$3-ca-key.pem" \
    -CAcreateserial -sha256 -days "$DAYS" -extfile "$4" -out "$1.pem" >/dev/null 2>&1
  rm -f "$1.csr"
}

cat > server-ext.cnf <<'EOF'
subjectAltName = DNS:localhost, DNS:edge, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
cat > gateway-ext.cnf <<'EOF'
subjectAltName = DNS:gateway, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF
cat > client-ext.cnf <<'EOF'
extendedKeyUsage = clientAuth
EOF

make_ca public   "edge-public-ca-TEST"
make_ca client   "edge-client-ca-TEST"
make_ca internal "edge-internal-ca-TEST"

# --- Client-CA database (revocation support) --------------------------------
# Customer/agent certs are issued via `openssl ca` (not `x509 -req`) so each
# issuance is recorded in a CA database — that record is what revoke-cert.sh
# (`openssl ca -revoke`) marks revoked before regenerating the CRL that nginx
# enforces (`ssl_crl`). Paths in the cnf are deliberately relative: every
# `openssl ca` invocation must run with the certs dir as cwd.
mkdir -p client-ca-db/newcerts
touch client-ca-db/index.txt
echo 1000 > client-ca-db/serial
echo 1000 > client-ca-db/crlnumber
cat > client-ca.cnf <<EOF
[ca]
default_ca = client_ca

[client_ca]
database         = ./client-ca-db/index.txt
new_certs_dir    = ./client-ca-db/newcerts
serial           = ./client-ca-db/serial
crlnumber        = ./client-ca-db/crlnumber
certificate      = ./client-ca.pem
private_key      = ./client-ca-key.pem
default_md       = sha256
default_days     = $DAYS
# CRL validity matches the leaf lifetime — a shorter window (e.g. 30d) would
# trip check-cert-expiry.sh's default warning on a freshly generated CRL.
default_crl_days = $DAYS
policy           = policy_cn
x509_extensions  = client_cert_ext
copy_extensions  = none
unique_subject   = no

[policy_cn]
commonName = supplied

[client_cert_ext]
extendedKeyUsage = clientAuth
basicConstraints = CA:FALSE
EOF

# $1=name  $2=CN — issue a client cert through the CA database (revocable).
issue_client() {
  openssl genrsa -out "$1-key.pem" 2048 >/dev/null 2>&1
  openssl req -new -key "$1-key.pem" -subj "/CN=$2" -out "$1.csr" >/dev/null 2>&1
  openssl ca -batch -config client-ca.cnf -in "$1.csr" -out "$1.pem" -notext >/dev/null 2>&1
  rm -f "$1.csr"
}

# Edge proxy public TLS leaf (client pins public-ca, not this leaf).
make_leaf edge-public "localhost" public server-ext.cnf
# A sample customer/agent client cert for edge mTLS — via the CA db (revocable).
issue_client customer-pilot "pilot-customer-agent"
# Gateway's own TLS leaf + the proxy's client cert (inner hop).
make_leaf gateway "gateway" internal gateway-ext.cnf
make_leaf proxy-client "edge-proxy" internal client-ext.cnf

# Empty initial CRL — nginx's ssl_crl needs the file to exist from first boot.
openssl ca -config client-ca.cnf -gencrl -out client-ca.crl >/dev/null 2>&1

# The pin a client would hardcode (SPKI SHA-256 of the public CA — pin the CA,
# not the leaf, so leaf renewals don't break clients; §5 of the spec).
PIN=$(openssl x509 -in public-ca.pem -pubkey -noout \
  | openssl pkey -pubin -outform der 2>/dev/null \
  | openssl dgst -sha256 -binary | openssl base64)
echo "$PIN" > public-ca.pin

echo "Wrote test PKI to $OUT"
echo "  public-ca SPKI pin (base64 sha256): $PIN"
