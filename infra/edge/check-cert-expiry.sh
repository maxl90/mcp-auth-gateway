#!/usr/bin/env bash
# Warn when edge PKI certificates (or the CRL) approach expiry — spec §9:
# "Alerting on cert expiry (30/14/7 days)". Cron/CI-friendly: exit 0 when all
# clear, exit 1 when anything is expired or inside the warning window, so a
# scheduled run can page on a nonzero exit.
#
# Usage:  check-cert-expiry.sh [CERTS_DIR] [WARN_DAYS]
#         CERTS_DIR defaults to ./certs next to this script; WARN_DAYS to 30.
#         Run three schedules (30/14/7) for escalating alerts, e.g.:
#           check-cert-expiry.sh "" 7   # tightest window, highest urgency
#
# Checks every *.pem certificate (keys are skipped) AND client-ca.crl's
# nextUpdate — an expired CRL makes nginx reject ALL client certs, which is a
# sneakier outage than an expired leaf.
set -uo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"

DIR="${1:-}"
[ -n "$DIR" ] || DIR="$(cd "$(dirname "$0")" && pwd)/certs"
WARN_DAYS="${2:-30}"
WARN_SECS=$((WARN_DAYS * 86400))

failures=0
now_epoch=$(date +%s)

days_left() {  # $1 = openssl date string; echoes days or "?" if date -d absent
  local end_epoch
  if end_epoch=$(date -d "$1" +%s 2>/dev/null); then
    echo $(((end_epoch - now_epoch) / 86400))
  else
    echo "?"
  fi
}

report() {  # $1=name $2=enddate $3=expired(yes/no) $4=warn(yes/no)
  local status="OK"
  [ "$4" = yes ] && status="WARN <${WARN_DAYS}d"
  [ "$3" = yes ] && status="EXPIRED"
  printf '%-26s %-26s %5s days  %s\n' "$1" "$2" "$(days_left "$2")" "$status"
  [ "$4" = yes ] || [ "$3" = yes ] && failures=$((failures + 1))
}

cd "$DIR" || { echo "certs dir not found: $DIR (run gen-certs.sh first)"; exit 1; }

printf '%-26s %-26s %s\n' "CERT" "NOT AFTER" "STATUS"
for pem in *.pem; do
  case "$pem" in *-key.pem) continue ;; esac
  end=$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | cut -d= -f2-) || continue
  [ -n "$end" ] || continue
  expired=no; openssl x509 -in "$pem" -noout -checkend 0 >/dev/null || expired=yes
  warn=no;    openssl x509 -in "$pem" -noout -checkend "$WARN_SECS" >/dev/null || warn=yes
  report "$pem" "$end" "$expired" "$warn"
done

# The CRL: openssl has no -checkend for CRLs, so compare nextUpdate directly.
if [ -f client-ca.crl ]; then
  next=$(openssl crl -in client-ca.crl -noout -nextupdate 2>/dev/null | cut -d= -f2-)
  if [ -n "$next" ]; then
    left=$(days_left "$next")
    expired=no; warn=no
    if [ "$left" != "?" ]; then
      [ "$left" -lt 0 ] && expired=yes
      [ "$left" -lt "$WARN_DAYS" ] && warn=yes
    fi
    report "client-ca.crl (nextUpdate)" "$next" "$expired" "$warn"
  fi
fi

echo ""
if [ "$failures" -gt 0 ]; then
  echo "$failures item(s) expired or within ${WARN_DAYS} days — rotate (gen-certs.sh / your CA) and reload."
  exit 1
fi
echo "All certificates clear of the ${WARN_DAYS}-day window."
