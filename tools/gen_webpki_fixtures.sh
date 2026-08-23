#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Regenerate tests/fixtures/webpki
# ---------------------------------------------------------------------------
#
# The TLS 1.3 client is checked against the certificate shapes real CAs issue,
# which means real DER produced by something that is not us. This script is
# how those fixtures came to exist.
#
#   rroot / rleaf     RSA-2048, leaf directly under a self-issued root.
#   eroot / eleaf     ECDSA P-256, same shape.
#   croot/cint/cleaf  a three-level path: root -> intermediate -> leaf. This
#                     is the only fixture that exercises path building; the
#                     other two are pinned-root cases where there is no path.
#
# Usage:
#   tools/gen_webpki_fixtures.sh              write into tests/fixtures/webpki
#   tools/gen_webpki_fixtures.sh <outdir>     write somewhere else
#
# Keys are freshly random on every run, so regenerating replaces every file.
set -euo pipefail

OUT="${1:-tests/fixtures/webpki}"
HOST="mail.fjord.example"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

cat > "$WORK/ca.ext" <<'EXT'
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
EXT

cat > "$WORK/int.ext" <<'EXT'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign
EXT

cat > "$WORK/leaf.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:$HOST
EXT

# root <name> <cn> <keyspec>
make_root() {
  local n="$1" cn="$2"
  openssl req -x509 -new -noenc -days 3650 -subj "/CN=$cn" \
    -extensions v3 -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n') \
    -key "$WORK/$n.key" -out "$WORK/$n.pem" 2>/dev/null
  openssl x509 -in "$WORK/$n.pem" -outform DER -out "$OUT/$n.der"
}

# signed <name> <cn> <issuer> <ext file> <days>
make_signed() {
  local n="$1" cn="$2" ca="$3" ext="$4" days="$5"
  openssl req -new -noenc -subj "/CN=$cn" -key "$WORK/$n.key" \
    -out "$WORK/$n.csr" 2>/dev/null
  openssl x509 -req -in "$WORK/$n.csr" -CA "$WORK/$ca.pem" \
    -CAkey "$WORK/$ca.key" -days "$days" -extfile "$ext" \
    -out "$WORK/$n.pem" 2>/dev/null
  openssl x509 -in "$WORK/$n.pem" -outform DER -out "$OUT/$n.der"
}

rsa_key() { openssl genrsa -out "$WORK/$1.key" 2048 2>/dev/null; }
ec_key()  { openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/$1.key" 2>/dev/null; }

# --- RSA pinned pair -------------------------------------------------------
rsa_key rroot; make_root rroot "Fjord RSA Root"
rsa_key rleaf; make_signed rleaf "$HOST" rroot "$WORK/leaf.ext" 365
openssl pkcs8 -topk8 -nocrypt -in "$WORK/rleaf.key" -outform DER \
  -out "$OUT/rleaf.pk8"

# --- ECDSA pinned pair -----------------------------------------------------
ec_key eroot; make_root eroot "Fjord EC Root"
ec_key eleaf; make_signed eleaf "$HOST" eroot "$WORK/leaf.ext" 365
# The engine signs with the raw scalar, so hand it the private value alone.
# P-256 scalars are always 32 bytes on the wire. OpenSSL prints a leading
# 00 when the high bit is set and prints nothing when the value is short, so
# both ends need fixing up rather than trusting what it emits.
scalar=$(openssl ec -in "$WORK/eleaf.key" -text -noout 2>/dev/null \
  | awk '/priv:/{f=1;next} /pub:/{f=0} f' | tr -d ' :\n')
while [ ${#scalar} -gt 64 ]; do scalar="${scalar#??}"; done
while [ ${#scalar} -lt 64 ]; do scalar="0$scalar"; done
printf '%s\n' "$scalar" > "$OUT/eleaf.scalar.hex"

# --- three-level chain -----------------------------------------------------
rsa_key croot; make_root croot "Fjord Chain Root"
rsa_key cint;  make_signed cint "Fjord Chain Intermediate" croot "$WORK/int.ext" 1825
rsa_key cleaf
openssl req -new -noenc -subj "/CN=$HOST" -key "$WORK/cleaf.key" \
  -out "$WORK/cleaf.csr" 2>/dev/null
openssl x509 -req -in "$WORK/cleaf.csr" -CA "$WORK/cint.pem" \
  -CAkey "$WORK/cint.key" -days 365 -extfile "$WORK/leaf.ext" \
  -out "$WORK/cleaf.pem" 2>/dev/null
openssl x509 -in "$WORK/cleaf.pem" -outform DER -out "$OUT/cleaf.der"
openssl pkcs8 -topk8 -nocrypt -in "$WORK/cleaf.key" -outform DER \
  -out "$OUT/cleaf.pk8"

# --- a chain that violates its own path length -----------------------------
#
# dint1 is marked pathlen:0, which says no CA may sit below it. dint2 does.
# A verifier that ignores pathLenConstraint accepts this; one that honours it
# refuses. Nothing else distinguishes it from the valid chain above.
rsa_key droot; make_root droot "Fjord Depth Root"
rsa_key dint1; make_signed dint1 "Fjord Depth Intermediate One" droot "$WORK/int.ext" 1825
rsa_key dint2
openssl req -new -noenc -subj "/CN=Fjord Depth Intermediate Two" \
  -key "$WORK/dint2.key" -out "$WORK/dint2.csr" 2>/dev/null
openssl x509 -req -in "$WORK/dint2.csr" -CA "$WORK/dint1.pem" \
  -CAkey "$WORK/dint1.key" -days 1825 -extfile "$WORK/ca.ext" \
  -out "$WORK/dint2.pem" 2>/dev/null
openssl x509 -in "$WORK/dint2.pem" -outform DER -out "$OUT/dint2.der"
openssl x509 -in "$WORK/dint1.pem" -outform DER -out "$OUT/dint1.der"
rsa_key dleaf
openssl req -new -noenc -subj "/CN=$HOST" -key "$WORK/dleaf.key" \
  -out "$WORK/dleaf.csr" 2>/dev/null
openssl x509 -req -in "$WORK/dleaf.csr" -CA "$WORK/dint2.pem" \
  -CAkey "$WORK/dint2.key" -days 365 -extfile "$WORK/leaf.ext" \
  -out "$WORK/dleaf.pem" 2>/dev/null
openssl x509 -in "$WORK/dleaf.pem" -outform DER -out "$OUT/dleaf.der"
openssl pkcs8 -topk8 -nocrypt -in "$WORK/dleaf.key" -outform DER \
  -out "$OUT/dleaf.pk8"

echo "wrote fixtures to $OUT"
