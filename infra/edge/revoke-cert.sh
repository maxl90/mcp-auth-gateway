#!/usr/bin/env bash
# Revoke a client cert and regenerate the CRL nginx enforces (spec §5/§7,
# ADR 008). This is HALF of the kill switch — also revoke the Entra app grant;
# either kills access independently.
#
# Usage:  ./revoke-cert.sh <cert.pem> [CERTS_DIR]
#         (CERTS_DIR defaults to ./certs next to this script)
#
# nginx reads ssl_crl at config load, so after revoking, reload the edge:
#   docker compose -f docker-compose.quickstart.yml -f deploy/compose/docker-compose.edge.yml \
#     exec edge nginx -s reload
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

CERT="${1:?usage: revoke-cert.sh <cert.pem> [CERTS_DIR]}"
DIR="${2:-"$(cd "$(dirname "$0")" && pwd)/certs"}"

# client-ca.cnf uses relative paths — openssl ca must run from the certs dir.
# Copy the cert in first: with MSYS path conversion disabled, a /c/... absolute
# path built by bash is unreadable by the Windows openssl binary; a relative
# path works everywhere. Revocation is recorded by the cert's serial, so the
# copy is equivalent to the original.
CERT_ABS="$(cd "$(dirname "$CERT")" && pwd)/$(basename "$CERT")"
cd "$DIR"
cp "$CERT_ABS" ./.revoke-tmp.pem

openssl ca -config client-ca.cnf -revoke ./.revoke-tmp.pem
openssl ca -config client-ca.cnf -gencrl -out client-ca.crl
rm -f ./.revoke-tmp.pem

echo "Revoked $(basename "$CERT_ABS"); client-ca.crl regenerated."
echo "Reload the edge to enforce it:  docker compose ... exec edge nginx -s reload"
echo "Remember the second kill switch: revoke the Entra app grant too."
